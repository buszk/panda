#!/usr/bin/env python3
# Test that OSI works for each generic qcow - Note we use subprocesses to call
# ourself to hack around the bug where that we can't support multiple panda
# objects in one script :(

import os
import subprocess
from sys import argv
from panda.images.qcows import SUPPORTED_IMAGES, VM_DIR, get_qcow

# If called as ./generic_tests.py, run each supported architecture
# if called as ./generic_tests.py [arch] test that arch

def driver(): # Drive all tests
    for gen_name, data in SUPPORTED_IMAGES.items():
        print(f"Testing generic={gen_name}...")
        assert(data.snapshot == 'root'), "Non-standard snapshot name"

        with open(f"/tmp/{gen_name}.stdout", "w") as out:
            with open(f"/tmp/{gen_name}.stderr", "w") as oute:
                try:
                    subprocess.run(["python", "./generic_tests.py", gen_name], stderr=oute, stdout=out)
                except subprocess.CalledProcessError:
                    print(f"\tFAILURE - check /tmp/{gen_name}.std{{out,err}} for details")

def runner(generic_name):
    '''
    Try to run a single generic image
    First run via CLI - load root snapshot, run a command and quit - check command output
    Then test via python to see if OSI works
    '''
    from panda import Panda, blocking, ffi
    data = SUPPORTED_IMAGES[generic_name]
    qcow_path = get_qcow(generic_name)

    # Check 1 - can we load with CLI
    assert(os.path.isfile(qcow_path)), f"Can't find qcow for {generic_name}"
    # Start panda with a 10s timeout and background it
    # then sleep 1s, connect to the serial port via telnet, run a command and capture output
    # then shutdown panda via monitor and check if output matches expected value
    cmd = f"timeout 10s    panda-system-{data.arch} -loadvm {data.snapshot} -m {data.default_mem}  {qcow_path} \
            -display none -serial telnet:localhost:4321,server,nowait \
            -monitor unix:/tmp/panda.monitor,server,nowait & \
            sleep 2; RES=$(echo 'whoami' | nc -vvv localhost 4321) && echo 'q' | nc -vvv -q1 -U /tmp/panda.monitor && echo \"RESULT: $RES\" | grep -q 'root'"
    print(cmd)
    p = subprocess.run(cmd, shell=True)
    if p.returncode != 0:
        raise RuntimeError("Failed to run CLI panda")
    print("\tCLI: PASS")

    # Check 2 - load with python and test OSI profile
    panda = Panda(generic=generic_name)
    assert(os.path.isdir(panda.build_dir)), f"Missing build dir {panda.build_dir}"
    panda.load_plugin("syscalls2")
    panda.load_plugin("osi")
    panda.load_plugin("osi_linux")

    seen = set()
    @panda.cb_before_block_exec
    def bbe(cpu, tb):
        proc = panda.plugins['osi'].get_current_process(cpu) 
        name = ffi.string(proc.name)
        if name not in seen:
            seen.add(name)

    @blocking
    def start():
        print("Starting...")
        panda.revert_sync("root")
        print("Running serial..")
        r = panda.run_serial_cmd("grep root /etc/passwd")
        assert("root:x" in r), "Failed to run command"
        panda.end_analysis()

    panda.queue_async(start)
    panda.run()
    assert(len(seen)), "Didn't observe any processes"
    print("\tPython: PASS")


if __name__ == '__main__':
    if len(argv) == 1:
        driver()
    else:
        runner(argv[1])
