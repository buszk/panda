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


using namespace std;

// These need to be extern "C" so that the ABI is compatible with
// QEMU/PANDA, which is written in C
extern "C" {
bool init_plugin(void *);
void uninit_plugin(void *);
}

#ifdef CONFIG_SOFTMMU

bool only_label_uninitialized_reads = true;

// a taint label
typedef uint32_t Tlabel;

// map from taint label to mmio addr
map<Tlabel,uint64_t> label2ioaddr;
map<uint64_t,Tlabel> ioaddr2label;

bool taint_on = false;

uint64_t first_instruction;


void enable_taint(CPUState *env, target_ulong pc) {
    if (!taint_on 
        && rr_get_guest_instr_count() > first_instruction) {
        printf ("tainted_dma plugin is enabling taint\n");
        taint2_enable_taint();
        taint_on = true;
    }
    return;
}

extern uint64_t input_index;


void label_dma(CPUState *env, const uint8_t *buf, hwaddr addr, size_t size, bool is_write) {

    if (!is_write) return;

    Addr mem;
    mem.typ = MADDR;
    mem.val.ma = addr;
    mem.off = 0;
    mem.flag = 0;


    Tlabel label;
    if (ioaddr2label.count(addr) > 0)  {
            // existing label
            label = ioaddr2label[addr];
    }
    else {
        // new label
        label = label2ioaddr.size() + 1;
        label2ioaddr[label] = addr;
        ioaddr2label[addr] = label;

        Panda__TaintedDmaLabel *tml = (Panda__TaintedDmaLabel*) malloc(sizeof(Panda__TaintedDmaLabel));
        *tml = PANDA__TAINTED_DMA_LABEL__INIT;
        tml->pc = panda_current_pc(first_cpu);;
        tml->label = label;
        tml->addr = addr;

        Panda__LogEntry ple = PANDA__LOG_ENTRY__INIT;
        ple.tainted_dma_label = tml;
        pandalog_write_entry(&ple);
        free(tml);

    }
    cerr << "symbolic_label[" << input_index << ":" << size << "]\n";
    for (int i=0; i<size; i++) {
            taint2_label_addr(mem, i, label);
            taint2_sym_label_addr(mem, i, input_index+i);
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

    pcb.replay_after_dma = label_dma;
    panda_register_callback(self, PANDA_CB_REPLAY_AFTER_DMA, pcb);

    return true;
#else
    return false;
#endif


}


void uninit_plugin(void *self) {
    
    
}

