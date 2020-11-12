#include "inttypes.h"

#define in_range(x, l, r) \
    (x >= l && x<= r)

static int llvm_translate_pc(uint64_t pc) {
    return pc >= 0xffffffffa0000000 ||
           in_range(pc, 0xffffffff81c62410, 0xffffffff81c62443) || //ioread16
           in_range(pc, 0xffffffff81c62450, 0xffffffff81c6247b) || //ioread32
           in_range(pc, 0xffffffff8346bc50, 0xffffffff8346bc69) || //__memcpy
           in_range(pc, 0xffffffff8346bc70, 0xffffffff8346bc78) || //memcpy_erms
           in_range(pc, 0xffffffff8346bc80, 0xffffffff8346bd8e) || //memcpy_orig
           0;
}
