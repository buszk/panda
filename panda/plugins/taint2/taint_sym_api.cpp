#ifndef __TAINT_SYM_API_H_
#define __TAINT_SYM_API_H_


#ifdef __cplusplus
#include <cstdint>
#endif
#define SHAD_LLVM
#include "taint2.h"
#include "taint_sym_api.h"
#include "panda/plugin.h"

#include <fstream>
#include <sstream>
#include <iostream>
z3::context context;
std::vector<z3::expr> path_constraints;
bool z3_failure = false;

void taint2_sym_label_addr(Addr a, int offset, uint32_t l) {
    assert(shadow);
    a.off = offset;
    auto loc = shadow->query_loc(a);
    if (loc.first) {
        std::string id("val_");
        std::stringstream ss;
        ss << std::hex << l;
        id += ss.str();
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
    static int count = 0;

    if (z3_failure) return;

    count ++;
    target_ulong current_pc = panda_current_pc(first_cpu);

    z3::expr pc = (concrete ? condition : !condition);
    pc = pc.simplify();
    z3::solver solver(context);
    if (pc.is_true() || pc.is_false())
        return;

    for (auto c: path_constraints) {
        solver.add(c);
    }

    // If this fail, z3 cannot solve current path
    // Possible reasons:
    //     Code not instrumented
    //     Unimplemented instructions
    switch (solver.check()) {
        case z3::check_result::unsat:
            std::cerr << "Error: Z3 find current path UNSAT "
                << std::hex << current_pc << std::dec << std::endl;
            z3_failure= true;
            return;
        case z3::check_result::unknown:
            std::cerr << "Warning: Z3 cannot sovle current path "
                << std::hex << current_pc << std::dec << std::endl;
            z3_failure= true;
            return;
        default:
            break;
    }

    solver.add(!pc);
    path_constraints.push_back(pc);

    // If this fail, current branch cannot be reverted
    if (solver.check() != z3::check_result::sat)
        return;

    std::ofstream ofs("/tmp/drifuzz_path_constraints", 
            first ? std::ofstream::out : std::ofstream::app);
    
    first = false;

    ofs << "========== Z3 Path Solver ==========\n";
    
    ofs << "Count: " << count << " Condition: " << concrete <<
           " PC: " << std::hex << current_pc << std::dec <<"\n";

    ofs << "Path constraint: \n" << pc << "\n";

    z3::model model(solver.get_model());
    for (int i = 0; i < model.num_consts(); i++) {
        z3::func_decl f = model.get_const_decl(i);
        z3::expr pc_not = model.get_const_interp(f);
        ofs << "Inverted value: " << f.name().str() << " = " << pc_not <<  "\n";
    }
    ofs << "========== Z3 Path Solver End ==========\n";
    ofs.close();

}


#endif
