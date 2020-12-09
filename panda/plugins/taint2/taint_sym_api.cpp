#ifndef __TAINT_SYM_API_H_
#define __TAINT_SYM_API_H_


#ifdef __cplusplus
#include <cstdint>
#endif
#define SHAD_LLVM
#include "taint2.h"
#include "taint_sym_api.h"
#include "panda/plugin.h"

#include <cstring>
#include <fstream>
#include <sstream>
#include <iostream>
#include <unordered_set>
#include <unordered_map>

extern char *pc_path;

z3::context context;
std::vector<z3::expr> path_constraints;

std::unordered_map<std::string, std::string> dsu;

void make_set(std::string str) {
    if (dsu.count(str) == 0)
        dsu[str] = str;
}

std::string find_set(std::string str) {
    assert(dsu.count(str) > 0);
    if (str == dsu[str])
        return str;
    return find_set(dsu[str]);
}

void union_sets(std::string a, std::string b) {
    a = find_set(a);
    b = find_set(b);
    if (a != b)
        dsu[b] = a;
}

bool same_set(std::string a, std::string b) {
    a = find_set(a);
    b = find_set(b);
    return a == b;
}

bool related(std::unordered_set<std::string> s, std::string str) {
    for (std::string e: s) {
        if (same_set(str, e))
            return true;
    }
    return false;
}

inline bool ishex(char c) {
    return (c >= '0' && c <= '9') ||
           (c >= 'a' && c <= 'f');
}

inline size_t hash_string(std::string str) {
    int fi = str.find("val_", 0);
    bool counting = true;
    size_t hash = 0;
    for (int i = 0; i < str.length(); i++) {
        if (i >= fi && i < fi+4) {
            counting = false;
        } 
        else if (!counting && ishex(str[i])) {
            
        }
        else if (!counting && !ishex(str[i])) {
            counting = true;
            fi = str.find("val_", fi+1);
            hash = ((hash << 5) + hash) + str[i];
        }
        else {
            hash = ((hash << 5) + hash) + str[i];
        }
    }
    return hash;
}

size_t hash_expr(z3::expr e) {
    std::stringstream ss;
    ss << e;
    return hash_string(ss.str());
}

uint64_t hash_int(uint64_t x) {
    x = (x ^ (x >> 30)) * UINT64_C(0xbf58476d1ce4e5b9);
    x = (x ^ (x >> 27)) * UINT64_C(0x94d049bb133111eb);
    x = x ^ (x >> 31);
    return x;
}

size_t hash_vars(std::unordered_set<std::string> vars) {
    int i;
    size_t h = 0;
    for (std::string str : vars) {
        i = strtol(str.substr(4).c_str(), NULL, 16);
        h ^= hash_int(i);
    }
    return h;
}
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
    std::unordered_set<std::string> pc_vars;

    target_ulong current_pc = first_cpu->panda_guest_pc;

    // ignore kernel code (possibly in memcpy)
    if (current_pc < 0xffffffffa0000000)
        return;

    count ++;

    z3::expr pc = (concrete ? condition : !condition);
    pc = pc.simplify();
    z3::solver solver(context);
    if (pc.is_true() || pc.is_false())
        return;

    solver.add(pc);
    // assert(solver.check() == z3::check_result::sat);
    if (solver.check() == z3::check_result::sat) {
        z3::model pc_model(solver.get_model());
        for (int i = 0; i < pc_model.num_consts(); i++) {
            z3::func_decl f = pc_model.get_const_decl(i);
            pc_vars.insert(f.name().str());
        }
    }

    for (auto it = pc_vars.begin(); it != pc_vars.end(); it++) {
        make_set(*it);
        if (it == pc_vars.begin()) continue;
        union_sets(*it, *pc_vars.begin());
    }

    solver = z3::solver(context);
    solver.add(pc);
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
                << " Condition: " << concrete
                << " PC: " << std::hex << current_pc << std::dec
                << " Path constraint:\n" << pc << "\n";
            return;
        case z3::check_result::unknown:
            std::cerr << "Warning: Z3 cannot sovle current path "
                << " Condition: " << concrete
                << " PC: " << std::hex << current_pc << std::dec <<"\n";
            return;
        default:
            break;
    }
    
    solver = z3::solver(context);
    for (auto c: path_constraints) {
        solver.add(c);
    }

    solver.add(!pc);
    path_constraints.push_back(pc);

    // If this fail, current branch cannot be reverted
    if (solver.check() != z3::check_result::sat)
        return;

    if (first)
        std::cerr << "Creating path constraints file!!!\n";

    std::ofstream ofs(pc_path, 
            first ? std::ofstream::out : std::ofstream::app);
    
    first = false;

    ofs << "========== Z3 Path Solver ==========\n";
    
    ofs << "Count: " << count << 
           " Condition: " << concrete <<
           " PC: " << std::hex << current_pc << 
           " Hash: " << hash_expr(condition) << 
           " Vars: " << hash_vars(pc_vars) << 
           "\n" << std::dec;

    ofs << "Path constraint: \n" << pc << "\n";

    z3::model model(solver.get_model());
    for (int i = 0; i < model.num_consts(); i++) {
        z3::func_decl f = model.get_const_decl(i);
        z3::expr pc_not = model.get_const_interp(f);
        if (related(pc_vars, f.name().str()))
            ofs << "Inverted value: " << f.name().str() << " = " << pc_not <<  "\n";
    }
    ofs << "========== Z3 Path Solver End ==========\n";
    ofs.close();

}


#endif
