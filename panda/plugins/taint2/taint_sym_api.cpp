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
std::vector<z3::expr> path_constraints;

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
    z3::expr pc = (concrete ? condition : !condition);
    z3::solver solver(context);
    if (unlikely(pc.simplify().is_true() || pc.simplify().is_false()))
        return;
    std::ofstream ofs("/tmp/drifuzz_path_constraints", 
            first ? std::ofstream::out : std::ofstream::app);
    
    first = false;
    
    ofs << "========== Z3 Path Solver ==========\n";
    

    ofs << "Path constraint: \n" << pc << "\n";

    for (auto c: path_constraints) {
        solver.add(c);
    }
    if (unlikely(solver.check() != z3::check_result::sat)) {
        for (auto c: path_constraints) {
            ofs << c << "\n";
        }
        ofs << "========== Z3 Path Solver End ==========\n";
        ofs.close();
        return;
    }
    path_constraints.push_back(pc);
    // If this fail, current path diverge, z3 cannot solve
    assert (solver.check() == z3::check_result::sat);

    solver.add(!pc);
    if (solver.check() == z3::check_result::sat) {
        z3::model model(solver.get_model());
        for (int i = 0; i < model.num_consts(); i++) {
            z3::func_decl f = model.get_const_decl(i);
            z3::expr pc_not = model.get_const_interp(f);
            ofs << "Inverted value: " << f.name().str() << " = " << pc_not <<  "\n";
        }
    }
    ofs << "========== Z3 Path Solver End ==========\n";
    ofs.close();

}


#endif
