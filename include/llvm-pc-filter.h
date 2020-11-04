#include "inttypes.h"

#define in_range(x, l, r) \
    (x >= l && x< r)
#define in_block(pc, target) \
    in_range(pc, target-0x100, target+0x100)

static int llvm_translate_pc(uint64_t pc) {
    return pc >= 0xffffffffa0000000 ||
           in_block(pc, 0xffffffff81c62479);
}