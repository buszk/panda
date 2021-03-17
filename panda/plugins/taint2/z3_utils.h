#ifndef _Z3_UTILS_H
#define _Z3_UTILS_H
#include <z3++.h>
#include <set>

uint64_t find_max(z3::expr addr, std::set<z3::expr*> constraints, int nbits);
uint64_t find_min(z3::expr addr, std::set<z3::expr*> constraints, int nbits);
uint64_t find_step(z3::expr addr, std::set<z3::expr*> constraints, int nbits,
                    uint64_t min, uint64_t max);

#endif