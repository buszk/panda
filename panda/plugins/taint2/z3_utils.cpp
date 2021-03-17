#include <z3_utils.h>

extern z3::context context;

uint64_t find_max(z3::expr addr, std::set<z3::expr*> constraints, int nbits) {
    assert(nbits <= 64);
    uint64_t min = 0;
    uint64_t max = -1;
    min = 0xffff000000000000;
    max = 0xffffffffffffffff;
    uint64_t mid;

    while (min < max-1) {
        mid = (min / 2) + (max / 2) + (min & max & 1);
        z3::solver solver(context);
        for (z3::expr *pc: constraints) {
            solver.add(*pc);
        }
        solver.add(z3::ugt(addr, context.bv_val(mid, nbits)));
        if (solver.check() == z3::check_result::unsat) {
            max = mid;
        }
        else {
            min = mid;
        }
    }
    z3::solver asolver(context);
    for (z3::expr *pc: constraints) {
        asolver.add(*pc);
    }
    asolver.add(addr == context.bv_val(max, nbits));
    assert(asolver.check() == z3::check_result::sat);

    // std::cerr << "addr: " << addr << std::endl;
    // std::cerr << "max: " << std::hex << max << std::dec << std::endl;
    return max;
}


uint64_t find_min(z3::expr addr, std::set<z3::expr*> constraints, int nbits) {
    assert(nbits <= 64);
    uint64_t min = 0;
    uint64_t max = -1;
    min = 0xffff000000000000;
    max = 0xffffffffffffffff;
    uint64_t mid;

    while (min < max-1) {
        mid = (min / 2) + (max / 2) + (min & max & 1);
        z3::solver solver(context);
        for (z3::expr *pc: constraints) {
            solver.add(*pc);
        }
        solver.add(z3::ult(addr, context.bv_val(mid, nbits)));
        if (solver.check() == z3::check_result::unsat) {
            min = mid;
        }
        else {
            max = mid;
        }
    }
    z3::solver asolver(context);
    for (z3::expr *pc: constraints) {
        asolver.add(*pc);
    }
    asolver.add(addr == context.bv_val(min, nbits));
    assert(asolver.check() == z3::check_result::sat);

    // std::cerr << "addr: " <<  addr << std::endl;
    // std::cerr << "min: " << std::hex << min << std::dec << std::endl;
    return min;
}

uint64_t find_step(z3::expr addr, std::set<z3::expr*> constraints, int nbits, 
                    uint64_t min, uint64_t max) {
    int step = 0;
    assert(nbits <= 64);
    for (step = 1; step < max-min && step < 64; step *= 2) {
        z3::solver solver(context);
        for (z3::expr *pc: constraints) {
            solver.add(*pc);
        }
        solver.add(addr == context.bv_val(min + step, nbits));
        if (solver.check() == z3::check_result::sat) {
            return step;
        }
    }
    return 0;
}