#ifndef __TAINT_SYM_API_H_
#define __TAINT_SYM_API_H_


#ifdef __cplusplus
#include <cstdint>
#endif
#define SHAD_LLVM
#include "taint2.h"
#include "taint_sym_api.h"
z3::context context;

void taint2_sym_label_addr(Addr a, int offset, uint32_t l) {
    assert(shadow);
    a.off = offset;
    auto loc = shadow->query_loc(a);
    if (loc.first) {
        std::string id("val");
        id += std::to_string(l);
        z3::expr *expr = new z3::expr(context.bv_const(id.c_str(), 8));
        // std::cout << "expr: " << *expr << "\n";
        loc.first->query_full(loc.second)->expr = expr;
    }
}

void *taint2_sym_query(Addr a) {
    assert(shadow);
    auto loc = shadow->query_loc(a);
    if (loc.first) {
        return loc.first->query_full(loc.second)->expr;
    }
    return nullptr;
}



#endif
