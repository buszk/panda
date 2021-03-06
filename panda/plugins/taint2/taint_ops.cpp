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

/*
 * Change Log:
 * dynamic check if there is a mul X 0 or mul X 1, for no taint prop or parallel
 * propagation respetively
 * 04-DEC-2018:  don't update masks on data that is not tainted; fix bug in
 *    taint2 deboug output for host memcpy
 */

#ifndef __STDC_FORMAT_MACROS
#define __STDC_FORMAT_MACROS
#endif

#include <cstdio>
#include <cstdarg>

#include <llvm/IR/Constants.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/Value.h>
#include <llvm/IR/Operator.h>

#include <llvm/IR/BasicBlock.h>
#include <llvm/IR/Function.h>

#include "qemu/osdep.h"        // needed for host-utils.h
#include "qemu/host-utils.h"   // needed for clz64 and ctz64

#include "panda/plugin.h"
#include "panda/plugin_plugin.h"
#define SHAD_LLVM
#include "shad.h"
#include "label_set.h"
#include "taint_ops.h"
#include "taint_utils.h"
#define CONC_LVL CONC_LVL_OFF
#include "concolic.h"
#include "z3_utils.h"
extern std::vector<z3::expr> *path_constraints;
extern std::set<z3::expr*> pc_subset(z3::expr expr);

uint64_t labelset_count;

extern "C" {

extern bool tainted_pointer;
extern bool detaint_cb0_bytes;

}

extern z3::context context;

std::string format_hex(uint64_t n) {
    std::stringstream stream;
    stream << std::hex << n;
    std::string result( stream.str() );
    return result;
}

/* Symbolic helper functions */
inline bool is_concrete_byte(z3::expr byte) {

    return byte.is_numeral() ||
           byte.is_true() || byte.is_false();

}

z3::expr get_byte(z3::expr *ptr, uint8_t offset, uint8_t concrete_byte, bool* symbolic) {

    if (ptr == nullptr)
        return context.bv_val(concrete_byte, 8);

    if (ptr->is_bool()) {
        if (ptr->is_true()) {
            assert(concrete_byte == 1);
            return context.bv_val(1, 8);
        }
        else if (ptr->is_false()) {
            assert(concrete_byte == 0);
            return context.bv_val(0, 8);
        }
        else {
            if (symbolic) *symbolic = true;
            return ite(*ptr, context.bv_val(1, 8), context.bv_val(0, 8));
        }
    }

    z3::expr expr = ptr->extract(8*offset + 7, 8*offset).simplify();
    if (symbolic) *symbolic = true;
    // assert(!is_concrete_byte(expr));
    return expr;
}

z3::expr bytes_to_expr(Shad *shad, uint64_t src, uint64_t size,
        uint64_t concrete, bool* symbolic) {
    z3::expr expr(context);
    for (uint64_t i = 0; i < size; i++) {
        auto src_tdp = shad->query_full(src+i);
        assert(src_tdp);
        uint8_t concrete_byte = (concrete >> (8*i))&0xff;
        if (i == 0) {
            if (src_tdp->full_size > size) {
                *symbolic = true; //?
                return src_tdp->full_expr->extract(size*8-1, 0).simplify();
            }
            else if (src_tdp->full_size == size) {
                // std::cerr << "fast path: " << *src_tdp->full_expr << std::endl;
                *symbolic = true;
                return *src_tdp->full_expr;
            }
            else if (src_tdp->full_size > 0) {
                *symbolic = true;
                expr = *src_tdp->full_expr;
                i += (src_tdp->full_size - 1);
            }
            else {
                expr = get_byte(src_tdp->expr, src_tdp->offset, concrete_byte, symbolic);
            }
        }
        else {
            expr = concat(get_byte(src_tdp->expr, src_tdp->offset, concrete_byte, symbolic), expr);
        }
    }
    return expr.simplify();
}

void invalidate_full(Shad *shad, uint64_t src, uint64_t size) {
    auto src_tdp = shad->query_full(src);
    src_tdp->full_expr = nullptr;
    src_tdp->full_size = 0;
    for (int i = 0; i < size; i++) {
        auto tdp = shad->query_full(src+i);
        tdp->expr = nullptr;
        tdp->offset = 0;
    }
}

void copy_symbols(Shad *shad_dest, uint64_t dest, Shad *shad_src, 
        uint64_t src, uint64_t size) {


    CDEBUG(std::cerr << "copy_symbols shad src " << src << " dst " << dest << "\n");
    for (uint64_t i = 0; i < size; i++) {
        auto src_tdp = shad_src->query_full(src+i);
        auto dst_tdp = shad_dest->query_full(dest+i);
        assert(src_tdp);

        if (i == 0) {
            if (dst_tdp->full_size > size) {
                // large to small
                dst_tdp->full_expr = new z3::expr(
                    src_tdp->full_expr->extract(8*size-1, 0).simplify());
                dst_tdp->full_size = size;
            }
            else if (dst_tdp->full_size > 0) {
                // small to large or equal
                dst_tdp->full_expr = src_tdp->full_expr;
                dst_tdp->full_size = src_tdp->full_size;
            }
        }

        dst_tdp->expr = src_tdp->expr;
        dst_tdp->offset = src_tdp->offset;
        // if (dst_tdp->expr)
        //     std::cerr << "expr: "  << * dst_tdp->expr <<
        //                 " offset: " << (int)dst_tdp->offset << "\n";
    }
}

void expr_to_bytes(z3::expr expr, Shad *shad, uint64_t dest, 
        uint64_t size) {
    z3::expr *ptr = new z3::expr(expr);
    if (ptr->is_numeral()) {
        invalidate_full(shad, dest, size);
        return;
    }
    for (uint64_t i = 0; i < size; i++) {
        auto dst_tdp = shad->query_full(dest+i);
        assert(dst_tdp);
        if (i == 0 && size != 1) {
            dst_tdp->full_expr = new z3::expr(expr);
            dst_tdp->full_size = size;
        }
        dst_tdp->expr = ptr;
        dst_tdp->offset = i;
    }
}

z3::expr icmp_compute(llvm::CmpInst::Predicate pred, z3::expr expr1, z3::expr expr2) {

    switch(pred) {
        case llvm::ICmpInst::ICMP_EQ:
            return expr1 == expr2;
        case llvm::ICmpInst::ICMP_NE:
            return expr1 != expr2;
        case llvm::ICmpInst::ICMP_UGT:
            return z3::ugt(expr1, expr2);
        case llvm::ICmpInst::ICMP_UGE:
            return z3::uge(expr1, expr2);
        case llvm::ICmpInst::ICMP_ULT:
            return z3::ult(expr1, expr2);
        case llvm::ICmpInst::ICMP_ULE:
            return z3::ule(expr1, expr2);
        case llvm::ICmpInst::ICMP_SGT:
            return expr1 > expr2;
        case llvm::ICmpInst::ICMP_SGE:
            return expr1 >= expr2;
        case llvm::ICmpInst::ICMP_SLT:
            return expr1 < expr2;
        case llvm::ICmpInst::ICMP_SLE:
            return expr1 <= expr2;
        default:
            assert(false);
            return z3::expr(context);
    }
}

z3::expr icmp_compute(llvm::CmpInst::Predicate pred, z3::expr expr1,
        uint64_t val, uint64_t nbytes) {
    assert(expr1.get_sort().is_bv());
    z3::expr expr2 = context.bv_val(val, nbytes*8);
    return icmp_compute(pred, expr1, expr2);
}

z3::expr bitop_compute(unsigned opcode, z3::expr expr1, z3::expr expr2) {
    switch(opcode) {
        case llvm::Instruction::And:
            return expr1 & expr2;
        case llvm::Instruction::Or:
            return expr1 | expr2;
        case llvm::Instruction::Xor:
            return expr1 ^ expr2;
        default:
            assert(false);
            return z3::expr(context);
    }
}

z3::expr bitop_compute(unsigned opcode, z3::expr expr1,
        uint64_t val, uint64_t nbytes) {
    assert(expr1.get_sort().is_bv());
    z3::expr expr2 = context.bv_val(val, nbytes*8);
    return bitop_compute(opcode, expr1, expr2);
}

void print_spread_info(llvm::Instruction *I) {
    CINFO(llvm::errs() << "Taint spread by: " << *I << '\n');

    if (I->getOpcode() == llvm::Instruction::ICmp) {
        CINFO(std::cerr << "ICmp address: " << std::hex 
                << first_cpu->panda_guest_pc << std::dec << '\n');
    }
}

/* taint2 functions */
void detaint_on_cb0(Shad *shad, uint64_t addr, uint64_t size);
void taint_delete(FastShad *shad, uint64_t dest, uint64_t size);

const int CB_WIDTH = 128;
const llvm::APInt NOT_LITERAL(CB_WIDTH, ~0UL, true);

static inline bool is_ram_ptr(uint64_t addr)
{
    return RAM_ADDR_INVALID !=
           qemu_ram_addr_from_host(reinterpret_cast<void *>(addr));
}

// Remove the taint marker from any bytes whose control mask bits go to 0.
// A 0 control mask bit means that bit does not impact the value in the byte (or
// impacts it in an irreversible fashion, so they gave up on calculating the
// mask).  This reduces false positives by removing taint from bytes which were
// formerly tainted, but whose values are no longer (reversibly) controlled by
// any tainted data.
void detaint_on_cb0(Shad *shad, uint64_t addr, uint64_t size)
{
    uint64_t curAddr = 0;
    for (int i = 0; i < size; i++)
    {
        curAddr = addr + i;
        TaintData td = *shad->query_full(curAddr);
        
        // query_full ALWAYS returns a TaintData object - but there's not really
        // any taint (controlled or not) unless there are labels too
        if ((td.cb_mask == 0) && (td.ls != NULL) && (td.ls->size() > 0))
        {
            taint_delete(shad, curAddr, 1);
            taint_log("detaint: control bits 0 for 0x%lx\n", curAddr);
        }
    }
}

// Memlog functions.

uint64_t taint_memlog_pop(taint2_memlog *taint_memlog) {
    uint64_t result = taint_memlog->ring[taint_memlog->idx];
    taint_memlog->idx = (taint_memlog->idx + TAINT2_MEMLOG_SIZE - 1) % TAINT2_MEMLOG_SIZE;;

    taint_log("memlog_pop: %lx\n", result);
    return result;
}

void taint_memlog_push(taint2_memlog *taint_memlog, uint64_t val) {
    taint_log("memlog_push: %lx\n", val);
    taint_memlog->idx = (taint_memlog->idx + 1) % TAINT2_MEMLOG_SIZE;
    taint_memlog->ring[taint_memlog->idx] = val;
}

// Bookkeeping.
void taint_breadcrumb(uint64_t *dest_ptr, uint64_t bb_slot) {
    *dest_ptr = bb_slot;
}

// Stack frame operations

void taint_reset_frame(Shad *shad)
{
    shad->reset_frame();
}

void taint_push_frame(Shad *shad)
{
    shad->push_frame(MAXREGSIZE * MAXFRAMESIZE);
}
void taint_pop_frame(Shad *shad)
{
    shad->pop_frame(MAXREGSIZE * MAXFRAMESIZE);
}

struct CBMasks {
    llvm::APInt cb_mask;
    llvm::APInt one_mask;
    llvm::APInt zero_mask;

    CBMasks()
        : cb_mask(CB_WIDTH, 0UL), one_mask(CB_WIDTH, 0UL),
          zero_mask(CB_WIDTH, 0UL)
    {
    }
};

static void update_cb(Shad *shad_dest, uint64_t dest, Shad *shad_src,
                      uint64_t src, uint64_t size, llvm::Instruction *I);

static inline CBMasks compile_cb_masks(Shad *shad, uint64_t addr,
                                       uint64_t size);
static inline void write_cb_masks(Shad *shad, uint64_t addr, uint64_t size,
                                  CBMasks value);

// Taint operations
void taint_copy(Shad *shad_dest, uint64_t dest, Shad *shad_src, uint64_t src,
                uint64_t size, llvm::Instruction *I)
{
    if (unlikely(src >= shad_src->get_size() || dest >= shad_dest->get_size())) {
        taint_log("  Ignoring IO RW\n");
        return;
    }

    taint_log("copy: %s[%lx+%lx] <- %s[%lx] ",
            shad_dest->name(), dest, size, shad_src->name(), src);
    taint_log_labels(shad_src, src, size);

    concolic_copy(shad_dest, dest, shad_src, src, size, I);

    if (I) update_cb(shad_dest, dest, shad_src, src, size, I);
}

void taint_parallel_compute(Shad *shad, uint64_t dest, uint64_t ignored,
                            uint64_t src1, uint64_t src2, uint64_t src_size,
                            uint64_t val1, uint64_t val2, llvm::Instruction *I)
{
    uint64_t shad_size = shad->get_size();
    if (unlikely(dest >= shad_size || src1 >= shad_size || src2 >= shad_size)) {
        taint_log("  Ignoring IO RW\n");
        return;
    }

    taint_log("pcompute: %s[%lx+%lx] <- %lx + %lx\n",
            shad->name(), dest, src_size, src1, src2);
    uint64_t i;
    bool changed = false;
    for (i = 0; i < src_size; ++i) {
        TaintData td = TaintData::make_union(
                *shad->query_full(src1 + i),
                *shad->query_full(src2 + i), true);
        changed |= shad->set_full(dest + i, td);
    }

    // Unlike mixed computes, parallel computes guaranteed to be bitwise.
    // This means we can honestly compute CB masks; in fact we have to because
    // of the way e.g. the deposit TCG op is lifted to LLVM.
    CBMasks cb_mask_1 = compile_cb_masks(shad, src1, src_size);
    CBMasks cb_mask_2 = compile_cb_masks(shad, src2, src_size);
    CBMasks cb_mask_out;
    if (I && I->getOpcode() == llvm::Instruction::Or) {
        cb_mask_out.one_mask = cb_mask_1.one_mask | cb_mask_2.one_mask;
        cb_mask_out.zero_mask = cb_mask_1.zero_mask & cb_mask_2.zero_mask;
        // Anything that's a literal zero in one operand will not affect
        // the other operand, so those bits are still controllable.
        cb_mask_out.cb_mask =
            (cb_mask_1.zero_mask & cb_mask_2.cb_mask) |
            (cb_mask_2.zero_mask & cb_mask_1.cb_mask);
    } else if (I && I->getOpcode() == llvm::Instruction::And) {
        cb_mask_out.one_mask = cb_mask_1.one_mask & cb_mask_2.one_mask;
        cb_mask_out.zero_mask = cb_mask_1.zero_mask | cb_mask_2.zero_mask;
        // Anything that's a literal one in one operand will not affect
        // the other operand, so those bits are still controllable.
        cb_mask_out.cb_mask =
            (cb_mask_1.one_mask & cb_mask_2.cb_mask) |
            (cb_mask_2.one_mask & cb_mask_1.cb_mask);
    }
    taint_log(
        "pcompute_cb: 0x%.16lx%.16lx +  0x%.16lx%.16lx = 0x%.16lx%.16lx",
        apint_hi_bits(cb_mask_1.cb_mask), apint_lo_bits(cb_mask_1.cb_mask),
        apint_hi_bits(cb_mask_2.cb_mask), apint_lo_bits(cb_mask_2.cb_mask),
        apint_hi_bits(cb_mask_out.cb_mask), apint_lo_bits(cb_mask_out.cb_mask));
    taint_log_labels(shad, dest, src_size);
    write_cb_masks(shad, dest, src_size, cb_mask_out);

    if (detaint_cb0_bytes)
    {
        detaint_on_cb0(shad, dest, src_size);
    }

    invalidate_full(shad, dest, src_size);
    if (!changed) return;

    switch(I->getOpcode()) {
        case llvm::Instruction::And:
        case llvm::Instruction::Or:
        case llvm::Instruction::Xor: {
            print_spread_info(I);
            for (int i = 0; i < src_size; i++) {
                uint8_t byte1 = (val1 >> (8*i))&0xff;
                uint8_t byte2 = (val2 >> (8*i))&0xff;
                bool symbolic = false;
                z3::expr expr1 = bytes_to_expr(shad, src1+i, 1, byte1, &symbolic);
                z3::expr expr2 = bytes_to_expr(shad, src2+i, 1, byte2, &symbolic);
                if (!symbolic) continue;
                z3::expr expr = bitop_compute(I->getOpcode(), expr1, expr2);
                
                // simplify because one input may be constant
                expr = expr.simplify();
                // std::cerr << "e1: " << expr1 << "\n";
                // std::cerr << "e2: " << expr2 << "\n";
                // std::cerr << "after: " << expr << "\n";
                if (!is_concrete_byte(expr))
                    expr_to_bytes(expr, shad, dest+i, 1);
            }
            break;
        }
        default: {
            CINFO(llvm::errs() << "Untracked taint_parallel_compute: " << *I << '\n');
        }

    }
}

static inline TaintData mixed_labels(Shad *shad, uint64_t addr, uint64_t size,
                                     bool increment_tcn)
{
    TaintData td(*shad->query_full(addr));
    for (uint64_t i = 1; i < size; ++i) {
        td = TaintData::make_union(td, *shad->query_full(addr + i), false);
    }

    if (increment_tcn) td.increment_tcn();
    return td;
}

static inline bool bulk_set(Shad *shad, uint64_t addr, uint64_t size,
                            TaintData td)
{
    uint64_t i;
    bool change = false;
    for (i = 0; i < size; ++i) {
        change |= shad->set_full(addr + i, td);
    }
    return change;
}

void taint_mix_compute(Shad *shad, uint64_t dest, uint64_t dest_size,
                       uint64_t src1, uint64_t src2, uint64_t src_size,
                       uint64_t val1, uint64_t val2, llvm::Instruction *I)
{
    TaintData td = TaintData::make_union(
            mixed_labels(shad, src1, src_size, false),
            mixed_labels(shad, src2, src_size, false),
            true);
    bool change = bulk_set(shad, dest, dest_size, td);
    taint_log("mcompute: %s[%lx+%lx] <- %lx + %lx ",
            shad->name(), dest, dest_size, src1, src2);
    taint_log_labels(shad, dest, dest_size);

    invalidate_full(shad, dest, dest_size);
    if (!change) return;

    switch(I->getOpcode()) {
    case llvm::Instruction::Sub:
    case llvm::Instruction::Add:
    case llvm::Instruction::UDiv:
    case llvm::Instruction::Mul:
    {
        print_spread_info(I);
        bool symbolic = false;
        z3::expr expr1 = bytes_to_expr(shad, src1, src_size, val1, &symbolic);
        z3::expr expr2 = bytes_to_expr(shad, src2, src_size, val2, &symbolic);

        if (!symbolic) break;

        z3::expr expr(context);
        if (I->getOpcode() == llvm::Instruction::Sub)
            expr = expr1 - expr2;
        else if (I->getOpcode() == llvm::Instruction::Add)
            expr = expr1 + expr2;
        else if (I->getOpcode() == llvm::Instruction::UDiv)
            expr = expr1 / expr2;
        else if (I->getOpcode() == llvm::Instruction::Mul)
            expr = expr1 * expr2;

        CDEBUG(std::cerr << "output expr: " << expr << "\n");

        expr_to_bytes(expr, shad, dest, src_size);
        break;
    }
    case llvm::Instruction::ICmp: {
        print_spread_info(I);
        bool symbolic = false;
        z3::expr expr1 = bytes_to_expr(shad, src1, src_size, val1, &symbolic);
        z3::expr expr2 = bytes_to_expr(shad, src2, src_size, val2, &symbolic);

        // CDEBUG(if (!symbolic) llvm::errs() << *I->getParent()->getParent());
        if (!symbolic) break;
        CDEBUG(std::cerr << "Value 1: " << expr1 << "\n");
        CDEBUG(std::cerr << "Value 2: " << expr2 << "\n");
        auto *CI = llvm::dyn_cast<llvm::ICmpInst>(I);
        assert(CI);
        z3::expr expr = icmp_compute(CI->getPredicate(), expr1, expr2);
        shad->query_full(dest)->expr = new z3::expr(expr);
        shad->query_full(dest)->offset = 0;
        break;
    }
    case llvm::Instruction::Call: {
        llvm::CallInst *CI = llvm::dyn_cast<llvm::CallInst>(I);

        if (CI->getCalledFunction() &&
                (CI->getCalledFunction()->getName() == "llvm.uadd.with.overflow.i32" ||
                CI->getCalledFunction()->getName() == "llvm.uadd.with.overflow.i8")) {
            assert(dest_size == 2 * src_size);
            bool symbolic = false;
            z3::expr expr1 = bytes_to_expr(shad, src1, src_size, val1, &symbolic);
            z3::expr expr2 = bytes_to_expr(shad, src2, src_size, val2, &symbolic);

            if (!symbolic) break;

            CDEBUG(std::cerr << "expr1: " << expr1 << "\n");
            CDEBUG(std::cerr << "expr2: " << expr2 << "\n");
            z3::expr expr = expr1 + expr2;
            CDEBUG(std::cerr << "expr: " << expr << "\n");

            expr_to_bytes(expr, shad, dest, src_size);

            z3::expr overflow = z3::ult(expr, expr1) && z3::ult(expr, expr2);
            overflow = overflow.simplify();
            CDEBUG(std::cerr << "overflow: " << overflow << "\n");
            auto dst_tdp = shad->query_full(dest+src_size);
            assert(dst_tdp);
            if (!overflow.is_true() && !overflow.is_false()) {
                dst_tdp->expr = new z3::expr(overflow);
                dst_tdp->offset = 0;
            }

            break;

        }
        else {
            CINFO(llvm::errs() << "Untracked call instruction: " << *I << "\n");
        }
        break;
    }        
    case llvm::Instruction::Shl:
    case llvm::Instruction::LShr:
    case llvm::Instruction::AShr: {
        print_spread_info(I);

        bool symbolic = false;
        z3::expr expr(context);
        z3::expr expr1 = bytes_to_expr(shad, src1, src_size, val1, &symbolic);
        z3::expr expr2 = bytes_to_expr(shad, src2, src_size, val2, &symbolic);

        if (!symbolic) break;

        switch (I->getOpcode())
        {
        case llvm::Instruction::Shl:
            expr = shl(expr1, expr2);
            break;
        case llvm::Instruction::LShr:
            expr = lshr(expr1, expr2);
            break;
        case llvm::Instruction::AShr:
            expr = ashr(expr1, expr2);
            break;
        default:
            assert(false);
            break;
        }
        expr = expr.simplify();
        // std::cerr << "result: " << expr << "\n";
        expr_to_bytes(expr, shad, dest, src_size);

        break;
    }
    default:
        CINFO(llvm::errs() << "Untracked taint_mix_compute instruction: " << *I << "\n");
        break;
    }

}

void taint_mul_compute(Shad *shad, uint64_t dest, uint64_t dest_size,
                       uint64_t src1, uint64_t src2, uint64_t src_size,
                       llvm::Instruction *inst, uint64_t arg1_lo,
                       uint64_t arg1_hi, uint64_t arg2_lo, uint64_t arg2_hi)
{
    llvm::APInt arg1 = make_128bit_apint(arg1_hi, arg1_lo);
    llvm::APInt arg2 = make_128bit_apint(arg2_hi, arg2_lo);

    bool isTainted1 = false;
    bool isTainted2 = false;
    for (int i = 0; i < src_size; ++i) {
        isTainted1 |= shad->query(src1+i) != NULL;
        isTainted2 |= shad->query(src2+i) != NULL;
    }
    if (!isTainted1 && !isTainted2) {
        taint_log("mul_com: untainted args \n");
        return; //nothing to propagate
    } else if (!(isTainted1 && isTainted2)){ //the case we do special stuff
        llvm::APInt cleanArg = isTainted1 ? arg2 : arg1;
        taint_log("mul_com: one untainted arg 0x%.16lx%.16lx \n",
                  apint_hi_bits(cleanArg), apint_lo_bits(cleanArg));
        if (cleanArg == 0) return ; // mul X untainted 0 -> no taint prop
        else if (cleanArg == 1) { //mul X untainted 1(one) should be a parallel taint
            taint_parallel_compute(shad, dest, dest_size, src1, src2, src_size,
                    arg1_lo, arg2_lo, inst);
            taint_log("mul_com: mul X 1\n");
            return;
        }
    }
    taint_mix_compute(shad, dest, dest_size, src1, src2, src_size,
            arg1_lo, arg2_lo, inst);
}

void taint_delete(Shad *shad, uint64_t dest, uint64_t size)
{
    taint_log("remove: %s[%lx+%lx]\n", shad->name(), dest, size);
    if (unlikely(dest >= shad->get_size())) {
        taint_log("Ignoring IO RW\n");
        return;
    }
    shad->remove(dest, size);
    invalidate_full(shad, dest, size);
}

void taint_set(Shad *shad_dest, uint64_t dest, uint64_t dest_size,
               Shad *shad_src, uint64_t src)
{
    bulk_set(shad_dest, dest, dest_size, *shad_src->query_full(src));
}

void taint_mix(Shad *shad, uint64_t dest, uint64_t dest_size, uint64_t src,
               uint64_t src_size, uint64_t concrete, llvm::Instruction *I)
{
    TaintData td = mixed_labels(shad, src, src_size, true);
    bool change = bulk_set(shad, dest, dest_size, td);
    taint_log("mix: %s[%lx+%lx] <- %lx+%lx ",
            shad->name(), dest, dest_size, src, src_size);
    taint_log_labels(shad, dest, dest_size);

    if (I) update_cb(shad, dest, shad, src, dest_size, I);

    invalidate_full(shad, dest, dest_size);
    if (!I) return;
    if (!change) return;

    uint64_t val = 0;
    llvm::Value *consted = llvm::isa<llvm::Constant>(I->getOperand(0)) ?
            I->getOperand(0) : I->getOperand(1);
    assert(consted);
    CDEBUG(llvm::errs() << "Immediate Value: " << *consted << '\n');
    if (auto intval = llvm::dyn_cast<llvm::ConstantInt>(consted)) {
        val = intval->getValue().getLimitedValue();
    }

    switch (I->getOpcode()) {
        case llvm::Instruction::ICmp: {
            print_spread_info(I);

            CDEBUG(llvm::errs() << "Concrete Value: " << format_hex(concrete) << '\n');
            
            bool symbolic = false;
            z3::expr expr1 = bytes_to_expr(shad, src, src_size, concrete, &symbolic);

            // CDEBUG(if (!symbolic) llvm::errs() << *I->getParent()->getParent());
            if (!symbolic) break;
            CDEBUG(std::cerr << "Symbolic value: " << expr1 << "\n");
            auto *CI = llvm::dyn_cast<llvm::ICmpInst>(I);
            assert(CI);

            z3::expr expr = icmp_compute(CI->getPredicate(), expr1, val, src_size);

            shad->query_full(dest)->expr = new z3::expr(expr);
            shad->query_full(dest)->offset = 0;
            break;
        }
        case llvm::Instruction::Shl:
        case llvm::Instruction::LShr:
        case llvm::Instruction::AShr: {
            assert(src_size == dest_size);
            print_spread_info(I);

            bool symbolic = false;
            z3::expr expr = bytes_to_expr(shad, src, src_size, concrete, &symbolic);
            
            // std::cerr << "pre: " << expr << "\n";
            if (!symbolic) break;

            switch (I->getOpcode())
            {
            case llvm::Instruction::Shl:
                expr = shl(expr, context.bv_val(val, dest_size*8));
                break;
            case llvm::Instruction::LShr:
                expr = lshr(expr, context.bv_val(val, dest_size*8));
                break;
            case llvm::Instruction::AShr:
                expr = ashr(expr, context.bv_val(val, dest_size*8));
                break;
            default:
                assert(false);
                break;
            }
            expr = expr.simplify();
            // std::cerr << "result: " << expr << "\n";
            expr_to_bytes(expr, shad, dest, src_size);

            break;
        }
        case llvm::Instruction::Sub:
        case llvm::Instruction::Add:
        case llvm::Instruction::UDiv:
        case llvm::Instruction::Mul:
        {
            print_spread_info(I);
            bool symbolic = false;
            z3::expr expr = bytes_to_expr(shad, src, src_size, concrete, &symbolic);
            if (!symbolic) break;

            CDEBUG(std::cerr << "Immediate: " << val << "\n");
            CDEBUG(std::cerr << "input expr: " << expr << "\n");

            if (I->getOpcode() == llvm::Instruction::Sub)
                expr = expr - context.bv_val(val, src_size*8);
            else if (I->getOpcode() == llvm::Instruction::Add)
                expr = expr + context.bv_val(val, src_size*8);
            else if (I->getOpcode() == llvm::Instruction::UDiv)
                expr = expr / context.bv_val(val, src_size*8);
            else if (I->getOpcode() == llvm::Instruction::Mul)
                expr = expr * context.bv_val(val, src_size*8);

                
            CDEBUG(std::cerr << "output expr: " << expr << "\n");

            expr_to_bytes(expr, shad, dest, src_size);
            break;
        }
        default:
            CINFO(llvm::errs() << "Untracked taint_mix instruction: " << *I << "\n");
            break;
    }

}

static const uint64_t ones = ~0UL;

void taint_pointer_run(uint64_t src, uint64_t ptr, uint64_t dest, bool is_store, uint64_t size);

// Model for tainted pointer is to mix all the labels from the pointer and then
// union that mix with each byte of the actual copied data. So if the pointer
// is labeled [1], [2], [3], [4], and the bytes are labeled [5], [6], [7], [8],
// we get [12345], [12346], [12347], [12348] as output taint of the load/store.
void taint_pointer(Shad *shad_dest, uint64_t dest, Shad *shad_ptr, uint64_t ptr,
                   uint64_t ptr_size, Shad *shad_src, uint64_t src,
                   uint64_t size, uint64_t is_store, llvm::Instruction *I)
{
    taint_log("ptr: %s[%lx+%lx] <- %s[%lx] @ %s[%lx+%lx]\n",
            shad_dest->name(), dest, size,
            shad_src->name(), src, shad_ptr->name(), ptr, ptr_size);

    if (unlikely(dest + size > shad_dest->get_size())) {
        taint_log("  Ignoring IO RW\n");
        return;
    } else if (unlikely(src + size > shad_src->get_size())) {
        taint_log("  Source IO.\n");
        src = ones; // ignore source.
    }

    // query taint on pointer either being read or written
    if (tainted_pointer & TAINT_POINTER_MODE_CHECK) {
        taint_pointer_run(src, ptr, dest, (bool) is_store, size);
    }

    // this is [1234] in our example
    TaintData ptr_td = mixed_labels(shad_ptr, ptr, ptr_size, false);
    if (src == ones) {
        bulk_set(shad_dest, dest, size, ptr_td);
    } else {
        bool change = false;
        for (unsigned i = 0; i < size; i++) {
            TaintData byte_td = *shad_src->query_full(src + i);
            TaintData dest_td = TaintData::make_union(ptr_td, byte_td, false);

            // Unions usually destroy controlled bits. Tainted pointer is
            // a special case.
            uint8_t oldCBMask = dest_td.cb_mask;
            dest_td.cb_mask = byte_td.cb_mask;
            if (detaint_cb0_bytes && (byte_td.cb_mask == 0) && (oldCBMask != 0))
            {
                taint_delete(shad_dest, (dest + i), 1);
                taint_log("detaint: control bits 0 for 0x%lx\n",
                    (dest + i));
            }
            else
            {
                change |= shad_dest->set_full(dest + i, dest_td);
            }
        }
        invalidate_full(shad_dest, dest, size);
        copy_symbols(shad_dest, dest, shad_src, src, size);
        if (change) {
            print_spread_info(I);
            // bool symbolic = false;
            // z3::expr ptr_expr = bytes_to_expr(shad_ptr, ptr, ptr_size, ptr, &symbolic);
            // if (!symbolic || !is_store) return;
            // symbolic = false;
            // z3::expr value_expr = bytes_to_expr(shad_src, src, size, 0, &symbolic); //unknown concrete value
            // if (!symbolic) return;
            // static std::set<uint64_t> dest_record;
            // if (dest_record.count(dest) > 0) return;
            // dest_record.insert(dest);
            // std::set<z3::expr*> pcs = pc_subset(ptr_expr.extract(31,0) == context.bv_val(dest, 32));
            // uint64_t min = find_min(ptr_expr, pcs, ptr_size*8);
            // uint64_t max = find_max(ptr_expr, pcs, ptr_size*8);
            // uint64_t step = find_step(ptr_expr, pcs, ptr_size*8, min, max);
            // std::cerr << std::hex;
            // std::cerr << "PC:" <<  first_cpu->panda_guest_pc << std::endl;
            // std::cerr << "Pointer min:  " << min << std::endl;
            // std::cerr << "Pointer max:  " << max << std::endl;
            // std::cerr << "Pointer step: " << step << std::endl;
            // std::cerr << "ptr val: " << dest << std::endl;
            // std::cerr << std::dec;
            // uint64_t memory_value;
            // uint64_t addr;
            // for (addr = min; addr <= max; addr += step) {
            //     cpu_physical_memory_read(addr&0xffffffff, &memory_value, size);
            //     symbolic = false;
            //     z3::expr else_expr = bytes_to_expr(shad_dest, addr&0xffffffff, size, memory_value, &symbolic);
            //     z3::expr ite_expr = ite(ptr_expr.extract(31,0) == context.bv_val(addr&0xffffffff, 32),
            //             value_expr, else_expr);
            //     std::cerr << "ite: " << ite_expr << std::endl;
            //     std::cerr << "ite: " << ite_expr.simplify() << std::endl;
            //     bulk_set(shad_dest, addr&0xffffffff, size, ptr_td);
            //     expr_to_bytes(ite_expr, shad_dest, addr&0xffffffff, size);
            // }
        }
    }
}

void taint_after_ld_run(uint64_t reg, uint64_t addr, uint64_t size);

// logically after taint transfer has happened for ld *or* st
void taint_after_ld(uint64_t reg, uint64_t memaddr, uint64_t size) {
    taint_after_ld_run(reg, memaddr, size);
}



void taint_sext(Shad *shad, uint64_t dest, uint64_t dest_size, uint64_t src,
                uint64_t src_size, llvm::Instruction *I)
{
    taint_log("taint_sext\n");
    concolic_copy(shad, dest, shad, src, src_size, I);
    bulk_set(shad, dest + src_size, dest_size - src_size,
            *shad->query_full(dest + src_size - 1));
    auto src_tdp = shad->query_full(dest + src_size - 1);
    if (src_tdp->expr) {
        z3::expr top_byte = get_byte(src_tdp->expr, src_tdp->offset, 0, nullptr);
        z3::expr expr = ite(
                (top_byte & 0x80) == context.bv_val(0x80, 8), 
                context.bv_val(0xff, 8), context.bv_val(0, 8));
        expr = expr.simplify();
        z3::expr *ptr = new z3::expr(expr);
        for (uint64_t i = dest + src_size; i < dest + dest_size; i++) {
            auto dst_tdp = shad->query_full(i);
            dst_tdp->expr = ptr;
            dst_tdp->offset = 0;
        }

    }
}

// Takes a (~0UL, ~0UL, ~0UL)-terminated list of (src, value, selector) tuples.
void taint_select(Shad *shad, uint64_t dest, uint64_t size, uint64_t selector,
                  uint64_t sel_, uint64_t sel_size, llvm::Instruction *I, 
                  uint64_t nargs, ...)
{
    va_list argp;
    uint64_t src, srcsel, concrete;
    uint8_t found = 0;
    bool sym = false;
    std::vector<std::pair<uint64_t, z3::expr>> sel2expr;
    z3::expr selector_expr(context);
    z3::expr src_expr(context);

    va_start(argp, nargs);
    src = va_arg(argp, uint64_t);
    concrete = va_arg(argp, uint64_t);
    srcsel = va_arg(argp, uint64_t);
    // Non-load instruction
    if (sel_ != ones) {
        if (sel_size < 8) sel_size = 8;
        // llvm::errs() << "TaintSelect: " << *I << "\n";
        // llvm::errs() << "selector: " << selector << "\n";
        selector_expr = bytes_to_expr(shad, sel_, sel_size/8, selector, &sym);
        // std::cerr << "selector_expr: " << selector_expr << "\n";
        if (src != ones)
            src_expr = bytes_to_expr(shad, src, size, concrete, &sym);
        else
            src_expr = context.bv_val(concrete, size*8);
    }

    while (!(src == ones && srcsel == ones)) {
        if (srcsel == selector) { // bingo!
            if (src != ones) { // otherwise it's a constant.
                taint_log("select (copy): %s[%lx+%lx] <- %s[%lx+%lx] ",
                          shad->name(), dest, size, shad->name(), src, size);
                if (sel_ == ones)
                    concolic_copy(shad, dest, shad, src, size, I);
                taint_log_labels(shad, dest, size);
            }
            found = 1;
        }
        
        if (sel_ != ones)
            sel2expr.push_back(std::make_pair<>(srcsel, src_expr));

        src = va_arg(argp, uint64_t);
        concrete = va_arg(argp, uint64_t);
        srcsel = va_arg(argp, uint64_t);
        if (sel_ != ones) {
            if (src != ones)
                src_expr = bytes_to_expr(shad, src, size, concrete, &sym);
            else
                src_expr = context.bv_val(concrete, size*8);
        }
    }
    va_end(argp);

    if (!found)
        tassert(false && "Couldn't find selected argument!!");

    invalidate_full(shad, dest, size);
    if (sel_ != ones && sym) {
        z3::expr result = sel2expr[sel2expr.size()-1].second;
        for (int i = sel2expr.size() -2; i >=0 ; i-- )
            result = ite(selector_expr == context.bv_val(sel2expr[i].first, sel_size), 
                        sel2expr[i].second, result);
        expr_to_bytes(result, shad, dest, size);
        // llvm::errs() << "Instruction " << *I << "returns the following\n";
        // std::cerr << result << std::endl;
        // assert(false);
    }
}

#define cpu_off(member) (uint64_t)(&((CPUArchState *)0)->member)
#define cpu_size(member) sizeof(((CPUArchState *)0)->member)
#define cpu_endoff(member) (cpu_off(member) + cpu_size(member))
#define cpu_contains(member, offset) \
    (cpu_off(member) <= (size_t)(offset) && \
     (size_t)(offset) < cpu_endoff(member))

static void find_offset(Shad *greg, Shad *gspec, uint64_t offset,
                        uint64_t labels_per_reg, Shad **dest, uint64_t *addr)
{
#ifdef TARGET_PPC
    if (cpu_contains(gpr, offset)) {
#elif defined TARGET_MIPS
    if (cpu_contains(active_tc.gpr, offset)) {
#else
    if (cpu_contains(regs, offset)) {
#endif
        *dest = greg;
#ifdef TARGET_PPC
        *addr = (offset - cpu_off(gpr)) * labels_per_reg / sizeof(((CPUArchState *)0)->gpr[0]);
#elif defined TARGET_MIPS
        // env->active_tc.gpr
        *addr = (offset - cpu_off(active_tc.gpr)) * labels_per_reg / sizeof(((CPUArchState *)0)->active_tc.gpr[0]);
#else
        *addr = (offset - cpu_off(regs)) * labels_per_reg / sizeof(((CPUArchState *)0)->regs[0]);
#endif
    } else {
        *dest= gspec;
        *addr= offset;
    }
}

bool is_irrelevant(int64_t offset) {
#ifdef TARGET_I386
    bool relevant = cpu_contains(regs, offset) ||
        cpu_contains(eip, offset) ||
        cpu_contains(fpregs, offset) ||
        cpu_contains(xmm_regs, offset) ||
        cpu_contains(xmm_t0, offset) ||
        cpu_contains(mmx_t0, offset) ||
        cpu_contains(cc_dst, offset) ||
        cpu_contains(cc_src, offset) ||
        cpu_contains(cc_src2, offset) ||
        cpu_contains(cc_op, offset) ||
        cpu_contains(df, offset);
    return !relevant;
#else
    return offset < 0 || (size_t)offset >= sizeof(CPUArchState);
#endif
}

// This should only be called on loads/stores from CPUArchState.
void taint_host_copy(uint64_t env_ptr, uint64_t addr, Shad *llv,
                     uint64_t llv_offset, Shad *greg, Shad *gspec, Shad *mem,
                     uint64_t size, uint64_t labels_per_reg, bool is_store,
                     llvm::Instruction *I)
{
    Shad *shad_src = NULL;
    uint64_t src = UINT64_MAX;
    Shad *shad_dest = NULL;
    uint64_t dest = UINT64_MAX;

    int64_t offset = addr - env_ptr;

    if (true == is_ram_ptr(addr)) {
        ram_addr_t ram_addr;
        __attribute__((unused)) RAMBlock *ram_block = qemu_ram_block_from_host(
            reinterpret_cast<void *>(addr), false, &ram_addr);
        assert(NULL != ram_block);

        shad_src = is_store ? llv : mem;
        src = is_store ? llv_offset : ram_addr;
        shad_dest = is_store ? mem : llv;
        dest = is_store ? ram_addr : llv_offset;
    } else if (is_irrelevant(offset)) {
        // Irrelevant
        taint_log("hostcopy: irrelevant\n");
        return;
    } else {
        Shad *state_shad = NULL;
        uint64_t state_addr = 0;

        find_offset(greg, gspec, (uint64_t)offset, labels_per_reg, &state_shad,
                    &state_addr);

        shad_src = is_store ? llv : state_shad;
        src = is_store ? llv_offset : state_addr;
        shad_dest = is_store ? state_shad : llv;
        dest = is_store ? state_addr : llv_offset;
    }
    taint_log("hostcopy: %s[%lx+%lx] <- %s[%lx+%lx] ", shad_dest->name(), dest,
              size, shad_src->name(), src, size);
    taint_log_labels(shad_src, src, size);
    concolic_copy(shad_dest, dest, shad_src, src, size, I);
}

void taint_host_memcpy(uint64_t env_ptr, uint64_t dest, uint64_t src,
                       Shad *greg, Shad *gspec, uint64_t size,
                       uint64_t labels_per_reg)
{
    int64_t dest_offset = dest - env_ptr, src_offset = src - env_ptr;
    if (dest_offset < 0 || (size_t)dest_offset >= sizeof(CPUArchState) ||
            src_offset < 0 || (size_t)src_offset >= sizeof(CPUArchState)) {
        taint_log("hostmemcpy: irrelevant\n");
        return;
    }

    Shad *shad_dest = NULL, *shad_src = NULL;
    uint64_t addr_dest = 0, addr_src = 0;

    find_offset(greg, gspec, (uint64_t)dest_offset, labels_per_reg,
            &shad_dest, &addr_dest);
    find_offset(greg, gspec, (uint64_t)src_offset, labels_per_reg,
            &shad_src, &addr_src);

    taint_log("hostmemcpy: %s[%lx+%lx] <- %s[%lx] (offsets %lx <- %lx) ",
            shad_dest->name(), dest, size, shad_src->name(), src,
            dest_offset, src_offset);
    taint_log_labels(shad_src, addr_src, size);
    Shad::copy(shad_dest, addr_dest, shad_src, addr_src, size);
    copy_symbols(shad_dest, addr_dest, shad_src, addr_src, size);
}

void taint_host_delete(uint64_t env_ptr, uint64_t dest_addr, Shad *greg,
                       Shad *gspec, uint64_t size, uint64_t labels_per_reg)
{
    int64_t offset = dest_addr - env_ptr;

    if (offset < 0 || (size_t)offset >= sizeof(CPUArchState)) {
        taint_log("hostdel: irrelevant\n");
        return;
    }
    Shad *shad = NULL;
    uint64_t dest = 0;

    find_offset(greg, gspec, offset, labels_per_reg, &shad, &dest);

    taint_log("hostdel: %s[%lx+%lx]\n", shad->name(), dest, size);

    shad->remove(dest, size);
    invalidate_full(shad, dest, size);
}

// Update functions for the controlled bits mask.
// After a taint operation, we try and update the controlled bit mask to
// estimate which bits are still attacker-controlled.
// The information is stored on a byte level. LLVM operations give us the
// information on how to reconstruct word-level values. We use that information
// to reconstruct and deconstruct the full mask.
static inline CBMasks compile_cb_masks(Shad *shad, uint64_t addr, uint64_t size)
{
    // Control bit masks are assumed to have a width of CB_WIDTH, we can't
    // handle more than CB_WIDTH / 8 bytes.
    tassert(size <= (CB_WIDTH / 8));

    CBMasks result;
    for (int i = size - 1; i >= 0; i--) {
        TaintData td = *shad->query_full(addr + i);
        result.cb_mask <<= 8;
        result.one_mask <<= 8;
        result.zero_mask <<= 8;
        result.cb_mask |= td.cb_mask;
        result.one_mask |= td.one_mask;
        result.zero_mask |= td.zero_mask;
    }
    return result;
}

static inline void write_cb_masks(Shad *shad, uint64_t addr, uint64_t size,
                                  CBMasks cb_masks)
{
    for (unsigned i = 0; i < size; i++) {
        TaintData td = *shad->query_full(addr + i);
        td.cb_mask =
            static_cast<uint8_t>(cb_masks.cb_mask.trunc(8).getZExtValue());
        td.one_mask =
            static_cast<uint8_t>(cb_masks.one_mask.trunc(8).getZExtValue());
        td.zero_mask =
            static_cast<uint8_t>(cb_masks.zero_mask.trunc(8).getZExtValue());
        cb_masks.cb_mask = cb_masks.cb_mask.lshr(8);
        cb_masks.one_mask = cb_masks.one_mask.lshr(8);
        cb_masks.zero_mask = cb_masks.zero_mask.lshr(8);
        shad->set_full(addr + i, td);
    }
}

//seems implied via callers that for dyadic operations 'I' will have one tainted and one untainted arg
static void update_cb(Shad *shad_dest, uint64_t dest, Shad *shad_src,
                      uint64_t src, uint64_t size, llvm::Instruction *I)
{
    if (!I) return;

    // do not update masks on data that is not tainted (ie. has no labels)
    // this is because some operations cause constants to be put in the masks
    // (eg. SHL puts 1s in lower bits of zero mask), and this would then
    // generate a spurious taint change report
    bool tainted = false;
    for (uint32_t i = 0; i < size; i++) {
        if (shad_src->query(src + i) != NULL) {
            tainted = true;
        }
    }

    if (tainted) {
        CBMasks cb_masks = compile_cb_masks(shad_src, src, size);
        llvm::APInt &cb_mask = cb_masks.cb_mask;
        llvm::APInt &one_mask = cb_masks.one_mask;
        llvm::APInt &zero_mask = cb_masks.zero_mask;

        llvm::APInt orig_one_mask = one_mask, orig_zero_mask = zero_mask;
        __attribute__((unused)) llvm::APInt orig_cb_mask = cb_mask;
        std::vector<llvm::APInt> literals;
        llvm::APInt last_literal = NOT_LITERAL; // last valid literal.
        literals.reserve(I->getNumOperands());

        for (auto it = I->value_op_begin(); it != I->value_op_end(); it++) {
            const llvm::Value *arg = *it;
            const llvm::ConstantInt *CI = llvm::dyn_cast<llvm::ConstantInt>(arg);
            llvm::APInt literal = NOT_LITERAL;
            if (NULL != CI) {
                literal = CI->getValue().zextOrSelf(CB_WIDTH);
            }
            literals.push_back(literal);
            if (literal != NOT_LITERAL)
                last_literal = literal;
        }

        // static int warning_count = 0;
        // if (10 > warning_count && NOT_LITERAL == last_literal) {
        //     fprintf(stderr,
        //             "%sWARNING: Could not find last literal value, control "
        //             "bits may be incorrect.\n",
        //             PANDA_MSG);
        //     warning_count++;
        //     if (warning_count == 10) {
        //         fprintf(stderr,
        //                 "%sLast literal warning emitted %d times, suppressing "
        //                 "warning.\n",
        //                 PANDA_MSG, warning_count);
        //     }
        // }

        int log2 = 0;

        unsigned int opcode = I->getOpcode();

        // guts of this function are in separate file so it can be more easily
        // tested without calling a function (which would slow things down even more)
#include "update_cb_switch.h"

        taint_log("update_cb: %s[%lx+%lx] CB (0x%.16lx%.16lx) -> "
                  "(0x%.16lx%.16lx), 0 (0x%.16lx%.16lx) -> (0x%.16lx%.16lx), 1 "
                  "(0x%.16lx%.16lx) -> (0x%.16lx%.16lx)\n",
                  shad_dest->name(), dest, size, apint_hi_bits(orig_cb_mask),
                  apint_lo_bits(orig_cb_mask), apint_hi_bits(cb_mask),
                  apint_lo_bits(cb_mask), apint_hi_bits(orig_one_mask),
                  apint_lo_bits(orig_one_mask), apint_hi_bits(one_mask),
                  apint_lo_bits(one_mask), apint_hi_bits(orig_zero_mask),
                  apint_lo_bits(orig_zero_mask), apint_hi_bits(zero_mask),
                  apint_lo_bits(zero_mask));

        write_cb_masks(shad_dest, dest, size, cb_masks);
    }

    // not sure it's possible to call update_cb with data that is unlabeled but
    // still has non-0 masks leftover from previous processing, so just in case
    // call detainter (if desired) even for unlabeled input
    if (detaint_cb0_bytes)
    {
        detaint_on_cb0(shad_dest, dest, size);
    }
}

void concolic_copy(Shad *shad_dest, uint64_t dest, Shad *shad_src,
                     uint64_t src, uint64_t size, llvm::Instruction *I)
{
    bool change = false;
    if (I && (I->getOpcode() == llvm::Instruction::And ||
            I->getOpcode() == llvm::Instruction::Or)) {
        llvm::Value *consted = llvm::isa<llvm::Constant>(I->getOperand(0)) ?
                I->getOperand(0) : I->getOperand(1);
        assert(consted);
        llvm::ConstantInt *intval = llvm::dyn_cast<llvm::ConstantInt>(consted);
        assert(intval);
        uint64_t val = intval->getValue().getLimitedValue();

        for (uint64_t i = 0; i < size; i++) {
            uint8_t mask = (val >> (8*i))&0xff;
            if (I->getOpcode() == llvm::Instruction::And) {
                if (mask == 0)
                    change |= shad_dest->set_full(dest + i, TaintData());
                else
                    change |= shad_dest->set_full(dest + i, *shad_src->query_full(src+i));
            }
            else if (I->getOpcode() == llvm::Instruction::Or) {
                if (mask == 0xff)
                    change |= shad_dest->set_full(dest + i, TaintData());
                else
                    change |= shad_dest->set_full(dest + i, *shad_src->query_full(src+i));
            }
        }
    } else {
        change = Shad::copy(shad_dest, dest, shad_src, src, size);
    }
    if (!I) return;
    invalidate_full(shad_dest, dest, size);
    if (!change) return;
    switch (I->getOpcode()) {
        case llvm::Instruction::And:
        case llvm::Instruction::Or:
        case llvm::Instruction::Xor: {
            uint64_t val = 0;
            print_spread_info(I);
            llvm::Value *consted = llvm::isa<llvm::Constant>(I->getOperand(0)) ?
                    I->getOperand(0) : I->getOperand(1);
            assert(consted);
            CDEBUG(llvm::errs() << "Value: " << *consted << '\n');
            if (auto intval = llvm::dyn_cast<llvm::ConstantInt>(consted)) {
                val = intval->getValue().getLimitedValue();
            }
            bool symbolic = false;
            for (int i = 0; i < size; i++) {
                uint8_t mask = (val >> (8*i))&0xff;
                // concrete value does not matter here (just use 0)
                // because concrete bytes won't propagate
                z3::expr expr1 = bytes_to_expr(shad_src, src+i, 1, 0, &symbolic);
                z3::expr expr = bitop_compute(I->getOpcode(), expr1, mask, 1);
                // simplify because one input is constant
                expr = expr.simplify();
                // std::cerr << "before: " << expr1 << "\nafter: " << expr << "\n";
                expr_to_bytes(expr, shad_dest, dest+i, 1);

            }
            break;
        }
        // shift by zero bits got here
        case llvm::Instruction::Shl:
        case llvm::Instruction::LShr:
        case llvm::Instruction::AShr:
        case llvm::Instruction::SExt:
            // Higher bits handled by caller
        case llvm::Instruction::Trunc:
        case llvm::Instruction::ZExt:
        case llvm::Instruction::Load:
        case llvm::Instruction::Store:
        case llvm::Instruction::IntToPtr:
        case llvm::Instruction::PtrToInt:
        case llvm::Instruction::Select:
            print_spread_info(I);
            copy_symbols(shad_dest, dest, shad_src, src, size);
            break;

        case llvm::Instruction::ExtractValue: {
            print_spread_info(I);
            if (auto CI = llvm::dyn_cast<llvm::CallInst>(I->getOperand(0))) {
                if (CI->getCalledFunction() &&
                        (CI->getCalledFunction()->getName() == "llvm.uadd.with.overflow.i32" ||
                        CI->getCalledFunction()->getName() == "llvm.uadd.with.overflow.i8")) {
                    copy_symbols(shad_dest, dest, shad_src, src, size);
                }
                else {
                    CINFO(llvm::errs() << "Untracked function\n");
                }
            }
            else {
                CINFO(llvm::errs() << "Untracked extractvalue\n");
            }

            break;
        }
        default:
            CINFO(llvm::errs() << "Untracked op: " << *I << "\n");
            break;
    }
}
