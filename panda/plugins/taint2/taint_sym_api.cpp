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
#include <ctime>
#include <fstream>
#include <sstream>
#include <iostream>
#include <unordered_set>
#include <unordered_map>

extern char *pc_path;
extern "C" {
    int (*gen_jcc_hook)(target_ulong, int*);
    
    uint64_t target_branch_pc;
    uint64_t after_target_limit;
}
z3::context context;
std::vector<z3::expr> *path_constraints = nullptr;
std::unordered_map<uint64_t, int> *conflict_pcs = nullptr;
static std::unordered_set<uint64_t> modeled_branches;
static bool visit_new_branch = false;
std::unordered_map<std::string, std::unordered_set<z3::expr *>> var2constr;

std::unordered_map<std::string, std::string> dsu;

std::unordered_set<std::string> vars_to_mod;

static uint64_t first_target_count = 0;
static uint64_t new_branch_count = 0;
static uint64_t target_counter = 0;
static bool skip_jcc_output = false;

static double model_check_time = 0;
static double model_print_time = 0;

__attribute__((destructor (65535)))
void print_jcc_output();

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
    if (a != b) {
        var2constr[a].insert(var2constr[b].begin(), var2constr[b].end());
        dsu[b] = a;
    }
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

std::unordered_set<std::string> vars_in_expr(z3::expr expr) {
    std::unordered_set<std::string> result;
    z3::solver solver(context);
    solver.add(expr);
    if (solver.check() == z3::check_result::sat) {
        z3::model pc_model(solver.get_model());
        for (int i = 0; i < pc_model.num_consts(); i++) {
            z3::func_decl f = pc_model.get_const_decl(i);
            result.insert(f.name().str());
        }
    }
    return result;
}

std::set<z3::expr*> pc_subset(z3::expr expr) {
    std::set<z3::expr*> result;
    std::unordered_set<std::string> vars = vars_in_expr(expr);
    for (auto var: vars) {
        result.insert(var2constr[find_set(var)].begin(), var2constr[find_set(var)].end());
    }
    return result;
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

    bool revertable = false;
    static bool first = true;
    bool jcc_mod_branch = false;
    static int count = 0;
    int jcc_mod_cond = -1;
    z3::expr pc(context);
    z3::solver solver(context);
    std::unordered_set<std::string> pc_vars;
    z3::check_result res;
    time_t start;

    target_ulong current_pc = first_cpu->panda_guest_pc;

    // ignore kernel code (possibly in memcpy)
    if (current_pc < 0xffffffffa0000000)
        return;
    count ++;
    std::cerr << "Count: " << count << std::hex <<
                " PC: " << current_pc << std::dec <<
                " condition: " << condition << "\n";

    if (gen_jcc_hook)
        if (gen_jcc_hook(current_pc, &jcc_mod_cond)) {
            if (jcc_mod_cond == 0 || jcc_mod_cond == 1)
                jcc_mod_branch = true;
            
            modeled_branches.insert(current_pc);
        }

    if (jcc_mod_branch)
        pc = (jcc_mod_cond ? condition: !condition);
    else
        pc = (concrete ? condition : !condition);
    pc = pc.simplify();

    if (jcc_mod_branch && pc.is_false()) {
        std::cerr << "JCC branch path constraint is false\n";
        conflict_pcs->insert(std::make_pair<>(current_pc, 2));
        return;
    }

    if (pc.is_true() || pc.is_false())
        return;

    pc_vars = vars_in_expr(pc);
    vars_to_mod.insert(pc_vars.begin(), pc_vars.end());

    for (auto it = pc_vars.begin(); it != pc_vars.end(); it++) {
        make_set(*it);
        if (it == pc_vars.begin()) continue;
        union_sets(*it, *pc_vars.begin());
    }

    solver.add(pc);
    // for (auto c: *path_constraints) {
    //     solver.add(c);
    // }
    std::set<z3::expr*> constraints;
    for (std::string var : pc_vars) {
        constraints.insert(var2constr[find_set(var)].begin(), var2constr[find_set(var)].end());
    }
    for (z3::expr *c: constraints) {
        solver.add(*c);
    }


    // If this fail, z3 cannot solve current path
    // Possible reasons:
    //     Code not instrumented
    //     Unimplemented instructions
    time(&start);
    res = solver.check();
    model_check_time += difftime(time(NULL), start);
    switch (res) {
        case z3::check_result::unsat:
            if (conflict_pcs->count(current_pc) == 0) {
                conflict_pcs->insert(std::make_pair<>(current_pc, concrete? 0: 1));
            }
            else if ((*conflict_pcs)[current_pc] == 2) {

            }
            else if ((*conflict_pcs)[current_pc] != (concrete ? 0: 1)) {
                conflict_pcs->insert(std::make_pair<>(current_pc, 2));
            }
            else if ((*conflict_pcs)[current_pc] == (concrete ? 0: 1)) {
                
            }

            std::cerr << "Error: Z3 find current path UNSAT "
                << " Count: " << count
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
    // for (auto c: *path_constraints) {
    //     solver.add(c);
    // }
    for (auto c: constraints) {
        solver.add(*c);
    }
    
    solver.add(!pc);
    path_constraints->push_back(pc);

    // z3::expr *ptr = &*path_constraints->rbegin();
    z3::expr *ptr = new z3::expr(pc);
    // std::cerr << "============\n";
    // std::cerr << *ptr << "\n";
    // std::cerr << pc << "\n";
    // std::cerr << "============\n";
    for (std::string var : pc_vars) {
        var2constr[find_set(var)].insert(ptr);
    }

    if (first)
        std::cerr << "Creating path constraints file!!!\n";

    std::ofstream ofs(pc_path, 
            first ? std::ofstream::out : std::ofstream::app);
    
    first = false;

    ofs << "========== Z3 Path Solver ==========\n";
    
    ofs << "Count: " << count << 
           " Condition: " << (jcc_mod_branch ? jcc_mod_cond : concrete) <<
           " PC: " << std::hex << current_pc << 
           " Hash: " << hash_expr(condition) << 
           " Vars: " << hash_vars(pc_vars) << 
           "\n" << std::dec;

    ofs << "Path constraint: \n" << pc << "\n";

    for (std::string val: pc_vars) {
        ofs << "Related input: " << val << "\n";
    }

    // Current branch can be reverted
    time(&start);
    res = solver.check();
    model_check_time += difftime(time(NULL), start);
    if (res == z3::check_result::sat) {
        revertable = true;
        time(&start);
        z3::model model(solver.get_model());
        for (int i = 0; i < model.num_consts(); i++) {
            z3::func_decl f = model.get_const_decl(i);
            z3::expr pc_not = model.get_const_interp(f);
            if (related(pc_vars, f.name().str()))
                ofs << "Inverted value: " << f.name().str() << " = " << pc_not <<  "\n";
        }
        model_print_time += difftime(time(NULL), start);
    }

    ofs << "========== Z3 Path Solver End ==========\n";
    ofs.close();

    
    if (revertable) {
        if (target_branch_pc) {

            if (current_pc == target_branch_pc) {
                if (first_target_count == 0)
                    first_target_count = count;
                target_counter ++;
            }

            if (visit_new_branch &&
                count > after_target_limit + new_branch_count) {

                std::cout << std::hex;
                std::cout << "[Drifuzz] Reached symbolic branch limit after branch " <<
                            target_branch_pc << std::endl;
                std::cout << std::dec;
                std::cout << "[Drifuzz] new_branch_count = " <<
                            new_branch_count << std::endl;
                std::cout << "[Drifuzz] first_target_count = " <<
                            first_target_count << std::endl;
                std::cout << "[Drifuzz] Exiting......\n";

                // Need to print before calling exit to resolve a z3 complaint
                print_jcc_output();
                skip_jcc_output = true;
                exit(0);
            }
            else if (!visit_new_branch && target_counter >= 2000) {
                
                std::cout << "[Drifuzz] Might got in infinite loop " << std::endl;
                std::cout << "[Drifuzz] Exiting......\n";

                // Need to print before calling exit to resolve a z3 complaint
                print_jcc_output();
                skip_jcc_output = true;
                exit(0);
            }

            if (!visit_new_branch && modeled_branches.count(current_pc) == 0) {
                visit_new_branch = true;
                new_branch_count = count;
            }
        }
        else {
            if (count > 10000) {
                std::cout << "[Drifuzz] To save some time. We end after " <<
                            10000 << " symbolic branch" << std::endl;
                std::cout << "[Drifuzz] Exiting......\n";
                print_jcc_output();
                skip_jcc_output = true;
                exit(0);
            }
        }
    }

}

__attribute__((constructor))
static void init_vars() {
    path_constraints = new std::vector<z3::expr>();
    conflict_pcs = new std::unordered_map<uint64_t, int>();
}

__attribute__((destructor))
static void fini_vars() {
    free(path_constraints);
    path_constraints = nullptr;
    free(conflict_pcs);
    conflict_pcs = nullptr;     
}

__attribute__((destructor (65535)))
void print_jcc_output() {

    printf("model_check_time: %.1f seconds\n", model_check_time);
    printf("model_print_time: %.1f seconds\n", model_print_time);

    if (skip_jcc_output) return;

    assert(path_constraints && conflict_pcs);
    
    z3::solver solver(context);
    std::ofstream ofs(pc_path, std::ofstream::app);
    
    ofs << "========== JCC Mod Output ==========\n";

    ofs << std::hex;
    for (auto p: *conflict_pcs) {
        ofs << "Conflict PC: " << p.first
            << " Condition: " << p.second << "\n";
    }
    ofs << std::dec;

    for (auto pc: *path_constraints) {
        solver.add(pc);
    }
    if (solver.check() == z3::check_result::sat) {
        z3::model model(solver.get_model());
        for (int i = 0; i < model.num_consts(); i++) {
            z3::func_decl f = model.get_const_decl(i);
            z3::expr pc_not = model.get_const_interp(f);
            if (related(vars_to_mod, f.name().str()))
                ofs << "Mod value: " << f.name().str() << " = " << pc_not <<  "\n";
        }
    }
    
    ofs << "========== JCC Mod Output End ==========\n";

    ofs.close();
}


#endif
