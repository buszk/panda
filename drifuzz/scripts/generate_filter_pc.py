#!/usr/bin/env python3
import sys
import subprocess
from os.path import join, abspath
from argparse import ArgumentParser

parser = ArgumentParser()
parser.add_argument('vmlinux', type=str)
args = parser.parse_args()

FILE_TEMPLATE='''
#include "inttypes.h"

#define in_range(x, l, r) \
    (x >= l && x<= r)

static int llvm_translate_pc(uint64_t pc) {
    return pc >= 0xffffffffa0000000 ||
           0;
}

'''
def objdump_output(vmlinux, symbol):
    cmd = [
        'objdump', f'--disassemble={symbol}', vmlinux  
    ]

    p = subprocess.Popen(cmd, stdout=subprocess.PIPE)
    p.wait()
    return p.stdout.read().decode('utf-8')

def parse_output(output):
    lines = output.split('\n')
    start = 0
    end = 0
    for line in lines:
        if len(line) > 16 and line[16] == ':':
            addr = int(line[:16], 16)
            if start == 0:
                start = addr
            end = addr
    if start == end:
        print(output)
    return start, end

def get_range(symbol):
    res = objdump_output(args.vmlinux, symbol)
    return parse_output(res)

def add_to_template(FILE_TEMPLATE, symbol):
    start, end = get_range(symbol)
    return FILE_TEMPLATE.replace(
        '0;\n',
        f'in_range(pc, {hex(start)}, {hex(end)}) || //{symbol}\n' \
        '           0;\n'
    )

funcs = [
    'ioread16',
    'ioread32',
    '__memcpy',
    'memcpy_erms',
    'memcpy_orig',
    'interrupt_entry',
    'restore_regs_and_return_to_kernel',
]
for func in funcs:
    FILE_TEMPLATE = add_to_template(FILE_TEMPLATE, func)
print(FILE_TEMPLATE)

print()
path = abspath(join(__file__, '..', '..', '..', 'include', 'llvm-pc-filter.h'))
with open(path, 'w') as f:
    f.write(FILE_TEMPLATE)