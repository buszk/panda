
#include "inttypes.h"

#define in_range(x, l, r)     (x >= l && x<= r)

static int llvm_translate_pc(uint64_t pc) {
    return pc >= 0xffffffffa0000000 ||
           in_range(pc, 0xffffffff81c623d0, 0xffffffff81c62401) || //ioread8
           in_range(pc, 0xffffffff81c62410, 0xffffffff81c62443) || //ioread16
           in_range(pc, 0xffffffff81c62450, 0xffffffff81c6247b) || //ioread32
           in_range(pc, 0xffffffff83486500, 0xffffffff83486519) || //__memcpy
           in_range(pc, 0xffffffff83486520, 0xffffffff83486528) || //memcpy_erms
           in_range(pc, 0xffffffff83486530, 0xffffffff8348663e) || //memcpy_orig
           in_range(pc, 0xffffffff83600920, 0xffffffff836009df) || //interrupt_entry
           in_range(pc, 0xffffffff83600aaf, 0xffffffff83600acc) || //restore_regs_and_return_to_kernel
           in_range(pc, 0xffffffff836009e0, 0xffffffff836009fc) || //common_spurious
           in_range(pc, 0xffffffff83600a00, 0xffffffff83600a0a) || //common_interrupt
           in_range(pc, 0xffffffff81006240, 0xffffffff81006407) || //prepare_exit_to_usermode
           in_range(pc, 0xffffffff81052e10, 0xffffffff81053be2) || //__switch_to
           in_range(pc, 0xffffffff83600170, 0xffffffff836001dd) || //__switch_to_asm
           0;
}

