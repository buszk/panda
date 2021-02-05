#include <inttypes.h>
#include <limits.h>

char *index_path = "/tmp/drifuzz_index";
char *pc_path = "/tmp/drifuzz_path_constraint";

uint64_t target_branch_pc = 0;
uint64_t after_target_limit = UINT64_MAX;

