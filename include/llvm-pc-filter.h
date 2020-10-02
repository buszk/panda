#include "inttypes.h"
static int llvm_translate_pc(uint64_t pc) {
    return pc >= 0xffffffffa0000000 ||
           (pc >= 0xffffffff81c62000 && pc < 0xffffffff81c63000);
}