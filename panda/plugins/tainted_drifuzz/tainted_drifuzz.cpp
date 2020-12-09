/* PANDABEGINCOMMENT
 * 
 * Authors:
 *  Tim Leek               tleek@ll.mit.edu
 *  Ryan Whelan            rwhelan@ll.mit.edu
 *  Joshua Hodosh          josh.hodosh@ll.mit.edu
 *  Michael Zhivich        mzhivich@ll.mit.edu
 *  Brendan Dolan-Gavitt   brendandg@gatech.edu
 * 
 * This work is licensed under the terms of the GNU GPL, version 2. 
 * See the COPYING file in the top-level directory. 
 * 
 PANDAENDCOMMENT */
// This needs to be defined before anything is included in order to get
// the PRIx64 macro
#define __STDC_FORMAT_MACROS

#include "panda/plugin.h"
#include "taint2/taint2.h"
#include "taint2/addr.h"

extern "C" {
#include <assert.h>
#include "taint2/taint2_ext.h"
#include "panda/plog.h"
}

#include <sstream>
#include <iostream>
#include <fstream>
#include <map>
#include <set>
#include <unordered_map>

/*
  Tainted MMIO labeling.

  This plugin's whole purpose in life is to apply taint labels to
  reads (loads) from memory-mapped io regions.  The idea is to use this
  to track taint for these and then employ other plugins such as
  tainted_branch to tell when/where that mmio data is being used to
  decide something.

  How does all this work?  It's a bit Rube Goldberg...
  
  If we have called panda_enable_memcb(), then we have access to
  callbacks that run in virtual memory load fns: 
  helper_le_ldY_XXX_panda, before and after the
  call to helper_le_ldY_XXX.  Great.

  We also have a callback in unassigned_mem_read which runs whenever
  there is a read attempted from an unassigned IO region. Excellent.

  Now the not so great.

  Recall that, the way the taint system works, its operation is
  interleaved with emulation.  More precisely, we have code that
  emulates a single guest instruction then code that updates the taint
  system appropriately, then code that emulates the next instruction,
  then more taint system updates for that instruction,
  etc. Unfortunately, this means that these seemingly useful callbacks
  (before & after load, as well as the unassigned mem io read one) all
  run BEFORE the corresponding operations take place to update the
  taint state.  Even the _after_ ones...  This means if we were to try
  to label a read using the PANDA_CB_VIRT_MEM_AFTER_READ, that label
  would be immediately wiped out, by the subsequent interleaved taint
  system update.  Ugh.

  We do have callbacks embedded in the taint system, however.  One of
  these, on_after_load, runs just after the taint has been transferred
  via a load instruction and gives one access to what register the
  load went to. 

  A little more background. Here's how the call chain works for when
  there is a memory mapped io read.

  softmmu_template.h:
    a: helper_le_ldY_XXX_panda
    b: helper_le_ldY_XXX
    c: io_read
  
  cputlb.c:
    d: io_readx

  memory.c:
    e: memory_region_dispatch_read
    f: unassigned_mem_read
    
   The call chain is
   a -> b -> c -> d -> e -> f 

   So that entire chain, a -> .. -> f takes place when there is a
   load.  THEN we update taint accordingly.
  
   Here's how the Rube Goldberg machine works that is this plugin.
   We end up using three of those callbacks to achieve our purpose.

   1. We unset a flag, is_unassigned_io, in fn before_virt_read,
   registered with PANDA_CB_VIRT_MEM_BEFORE_READ. This is happening,
   effectively, in "a".

   2. We set that flag if we ever end up in "f".  We do this in
   saw_unassigned_io_read, which is registered with
   PANDA_CB_UNASSIGNED_IO_READ.

   3. Finally, we register label_io_read to run at on_after_load.
   That callback checks if the value is_unassigned_io is true, which
   means that the memory read that just happened was from unassigned io.
   This means we can apply taint labels to the register into which the
   read went.

*/

extern char *index_path;
extern char *pc_path;


using namespace std;

// These need to be extern "C" so that the ABI is compatible with
// QEMU/PANDA, which is written in C
extern "C" {
bool init_plugin(void *);
void uninit_plugin(void *);
}

#ifdef CONFIG_SOFTMMU

bool only_label_uninitialized_reads = true;
uint32_t label, last_dma_label;

bool taint_on = false;
bool is_unassigned_io;
bool is_mmio;
size_t mmio_size;
uint64_t value;
target_ulong virt_addr;

uint64_t first_instruction;

bool read_taint_mem = false;
target_ulong last_virt_read_pc;

unordered_map<uint64_t,uint64_t> recorded_index;

uint64_t get_number(string line, string key, bool hex) {
    int index = line.find(key);
    int result = 0;
    if (index >= 0 && index <= line.length()) {
        index += key.size();
        index += 2;
        while (line[index] != ',' && line[index] != ' ' && index < line.length()) {
            result *= hex ? 16 : 10;
            if (line[index] >= 'a' && line[index] <= 'f') {
                result += 10;
                result += line[index] -'a';
            }
            else {
                result += line[index] - '0';
            }
            index ++;
        }
    }
    return result;
}

void parse_index() {
    string line;
    ifstream infile(index_path);
    getline(infile, line);
    while (line != "") {
        recorded_index.insert({
                get_number(line, "input_index", true),
                get_number(line, "size", false)       
        });
        getline(infile, line);
    }
}

void enable_taint(CPUState *env, target_ulong pc) {
    if (!taint_on 
        && rr_get_guest_instr_count() > first_instruction) {
        printf ("tainted_mmio plugin is enabling taint\n");
        taint2_enable_taint();
        taint_on = true;
        parse_index();
    }
    return;
}


target_ulong bvr_pc;

void before_virt_read(CPUState *env, target_ptr_t pc, target_ptr_t addr,
                     size_t size) {
    // clear this before every read
    is_unassigned_io = false;
    is_mmio = false;
    virt_addr = addr;
    bvr_pc = first_cpu->panda_guest_pc;

    return;
}

void before_phys_read(CPUState *env, target_ptr_t pc, target_ptr_t addr,
                          size_t size) {
    // Check if last read of taint memory is not handled
    if (!taint_on) return;
    if (read_taint_mem) {
        // printf("Warning: PC[%lx] read tainted memory in TCG mode\n", last_virt_read_pc);
        read_taint_mem = false;
    }
    // 1G memory boundary check
    // IO address can go above
    if (addr >= 0x40000000) return;

    for (int i = 0; i < size; i++) {
        QueryResult qr;
        // taint2_query_ram_full(addr+i, &qr);
        if (taint2_query_ram(addr+i)) {
        // if (qr.num_labels > 0) {
        //     if (qr.ls && ((set<TaintLabel> *)qr.ls)->count(last_dma_label) > 0) {
        //         printf("PC %lx read last dma label\n", pc);
        //     }
            read_taint_mem = true;
            last_virt_read_pc = first_cpu->panda_guest_pc;
            break;
        }
    }
}


hwaddr read_addr;
target_ulong suior_pc;

bool saw_unassigned_io_read(CPUState *env, target_ulong pc, hwaddr addr, 
                            size_t size, uint64_t *val) {

    is_unassigned_io = true;
    mmio_size = size;
    read_addr = addr;
    suior_pc = first_cpu->panda_guest_pc;


	assert (bvr_pc = suior_pc);
    return false;
}

void saw_mmio_read(CPUState *env, target_ptr_t physaddr, target_ptr_t vaddr, 
                            size_t size, uint64_t *val) {
    // cerr << "tainted_mmio: pc=" << hex << first_cpu->panda_guest_pc 
    //      << ": Saw mmio read virt_addr=" 
    //      << vaddr << " addr=" << physaddr << dec << "\n";
    is_mmio = true;
    mmio_size = size;
    read_addr = physaddr;
    value = *val;
    suior_pc = first_cpu->panda_guest_pc;
}


extern uint64_t last_input_index;
extern uint64_t input_index;

void label_io_read(Addr reg, uint64_t paddr, uint64_t size) {

    // yes we need to use a different one here than above
    target_ulong pc = first_cpu->panda_guest_pc;

    read_taint_mem = false;

    if (!(pc == bvr_pc && pc == suior_pc))
        return;


    if (!is_unassigned_io && !is_mmio) return;


    if (!taint_on) return;

    bool label_it = false;
    if (only_label_uninitialized_reads) {
        cerr << "Unassigned mmio read of " << hex << read_addr << dec << " \n";
        label_it = true;
    }
    if (!only_label_uninitialized_reads) {
        label_it = true;
    }
    if (label_it) {
        if (!execute_llvm)
            panda_enable_llvm();
        reg.off = 0;

        assert (reg.typ == LADDR);
        if (recorded_index.count(last_input_index) > 0 &&
            recorded_index[last_input_index] == mmio_size) {
            cerr << "label_io Laddr[" << reg.val.la << "]\n";
            cerr << "symbolic_label[" << hex << last_input_index << dec << ":" << mmio_size << "]\n";

            cerr << "... tainting register destination\n";
            cerr << "Taint label=" << label << " for io addr="
                 << hex << read_addr << " size=" << dec << mmio_size << "\n";

            for (int i=0; i<mmio_size; i++) {
                taint2_label_addr(reg, i, label);
                taint2_sym_label_addr(reg, i, last_input_index+i);
            }
        }
        label ++;
    }    
}

void label_dma(CPUState *env, const uint8_t *buf, hwaddr addr, size_t size, bool is_write) {

    if (!is_write) return;

    Addr mem;
    mem.typ = MADDR;
    mem.val.ma = addr;
    mem.off = 0;
    mem.flag = 0;
    static int label = 0;

    if (recorded_index.count(input_index) > 0 &&
        recorded_index[input_index] == size) {
        cerr << hex;
        cerr << "label_dma addr[" << addr << "]\n";
        cerr << "symbolic_label[" << input_index << ":" << size << "]\n";
        cerr << dec;

        for (int i=0; i<size; i++) {
            taint2_label_addr(mem, i, label);
            taint2_sym_label_addr(mem, i, input_index+i);
        }
        last_dma_label = label;
        label ++;
    }
}

#endif

bool init_plugin(void *self) {

#ifdef CONFIG_SOFTMMU

    // taint2 must be on
    panda_require("taint2");
    // and we need its api
    assert(init_taint2_api());    

    // this makes sure we know, in the taint system, the pc for every instruction
    panda_enable_precise_pc();

    // enables the before/after virt mem read / write callbacks
    panda_enable_memcb();

    panda_arg_list *args = panda_get_args("tainted_mmio");
    only_label_uninitialized_reads = panda_parse_bool_opt(args, "uninit", "if set this means we will only label reads from uninitialized mmio regions");

	// enable taint at this instruction
    first_instruction = panda_parse_uint64(args, "first_instruction", 0);

    panda_cb pcb;
    pcb.before_block_translate = enable_taint;
    panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_TRANSLATE, pcb);

    pcb.virt_mem_before_read = before_virt_read;
    panda_register_callback(self, PANDA_CB_VIRT_MEM_BEFORE_READ, pcb);
    
    pcb.phys_mem_before_read = before_phys_read;
    panda_register_callback(self, PANDA_CB_PHYS_MEM_BEFORE_READ, pcb);

    pcb.replay_after_dma = label_dma;
    panda_register_callback(self, PANDA_CB_REPLAY_AFTER_DMA, pcb);

    if (only_label_uninitialized_reads) {
        cerr << "tainted_mmio: only labeling uninitialized mmio reads\n";
        pcb.unassigned_io_read = saw_unassigned_io_read;
        panda_register_callback(self, PANDA_CB_UNASSIGNED_IO_READ, pcb);
    }
    else {
        cerr << "tainted_mmio: labeling all mmio reads\n";
        pcb.mmio_after_read = saw_mmio_read;
        panda_register_callback(self, PANDA_CB_MMIO_AFTER_READ, pcb);
    }

    PPP_REG_CB("taint2", on_after_load, label_io_read);
    return true;
#else
    return false;
#endif


}


void uninit_plugin(void *self) {
    
    
}

