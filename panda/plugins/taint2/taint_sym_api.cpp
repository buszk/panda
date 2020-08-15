#ifndef __TAINT_SYM_API_H_
#define __TAINT_SYM_API_H_


#ifdef __cplusplus
#include <cstdint>
#endif
#define SHAD_LLVM
#include "taint2.h"
#include "taint_sym_api.h"

#include <fstream>
z3::context context;

void taint2_sym_label_addr(Addr a, int offset, uint32_t l) {
    assert(shadow);
    a.off = offset;
    auto loc = shadow->query_loc(a);
    if (loc.first) {
        std::string id("val_");
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

z3::expr *taint2_sym_query_expr(Addr a) {
    return (z3::expr *) taint2_sym_query(a);
}

void reg_branch_pc(z3::expr condition, bool concrete) {

    static bool first = true;
    std::ofstream ofs("/tmp/drifuzz_path_constraints", first ? std::ofstream::out : std::ofstream::app);
    z3::expr pc = (concrete ? condition : !condition);
    ofs << "Path constraint: \n" << pc << "\n";

    z3::solver solver(context);
    solver.add(!pc);
    if (solver.check() != z3::check_result::sat) return;
    z3::model model(solver.get_model());
    ofs << "Model: \n" << model << "\n";
    for (int i = 0; i < model.num_consts(); i++) {
        z3::func_decl f = model.get_const_decl(i);
        z3::expr pc_not = model.get_const_interp(f);
        ofs << "Revert value: " << f.name() << " = " << pc_not <<  "\n";
    }
    ofs.close();
    first = false;

}


#endif
