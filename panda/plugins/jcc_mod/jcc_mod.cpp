
#include "panda/plugin.h"

extern "C" {
    bool init_plugin(void *);
    void uninit_plugin(void *);
    extern int (*gen_jcc_hook)(target_ulong, int*);
}
#include <unordered_map>

std::unordered_map<target_ulong, int> branch_mod;

int jcc_hook(target_ulong pc, int* cond) {
    if (branch_mod.count(pc) > 0) {
        *cond = branch_mod[pc];
        return 1;
    }
    return 0;
}

bool init_plugin(void *self) {
    panda_arg_list *args = panda_get_args("jcc_mod");
    for (int i = 0; i < args->nargs; i++) {
        target_ulong pc = strtoull(args->list[i].key, NULL, 16);
        int cond = strtol(args->list[i].value, NULL, 0);
        branch_mod[pc] = cond;
    }

    assert(!gen_jcc_hook && "Hook cannot exist before plugin");
    gen_jcc_hook = jcc_hook;
    return true;
}

void uninit_plugin(void *self) { 

}