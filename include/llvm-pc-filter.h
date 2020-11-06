#include "inttypes.h"

#define in_range(x, l, r) \
    (x >= l && x<= r)
#define in_block(pc, target) \
    in_range(pc, target-0x100, target+0x100)

static int llvm_translate_pc(uint64_t pc) {
    return pc >= 0xffffffffa0000000 ||
           in_block(pc, 0xffffffff81c62479) || //readl
           in_range(pc, 0xffffffff8346bc50, 0xffffffff8346bc69) || //__memcpy
           in_range(pc, 0xffffffff8346bc70, 0xffffffff8346bc78) || //memcpy_erms
           in_range(pc, 0xffffffff8346bc80, 0xffffffff8346bd8e) || //memcpy_orig
           0;
}