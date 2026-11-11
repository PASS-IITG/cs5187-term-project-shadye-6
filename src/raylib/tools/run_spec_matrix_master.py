import os, glob, subprocess

TEST_DIR = "/tmp/gltf_spec_tests"
BIN_MASTER = "/tmp/test_raylib_importer_master"

test_files = sorted(glob.glob(f"{TEST_DIR}/*.gltf"))
print(f"{'Test Case':<38} | {'Pristine Master Behavior'}")
print("-" * 80)

env = dict(os.environ,
           ASAN_OPTIONS="abort_on_error=0:symbolize=1",
           UBSAN_OPTIONS="print_stacktrace=1:halt_on_error=0")

for tf in test_files:
    tname = os.path.basename(tf).replace(".gltf", "")
    p = subprocess.run([BIN_MASTER, tf], env=env, capture_output=True, text=True, errors="replace")
    out = p.stdout + "\n" + p.stderr
    
    status = "OK"
    if "ERROR: AddressSanitizer:" in out:
        if "SEGV" in out:
            # find address
            addr = [l for l in out.splitlines() if "SEGV on" in l]
            status = f"CRASH: ASan SEGV ({addr[0].split('SEGV on')[1].split()[0] if addr else ''})"
        elif "heap-buffer-overflow" in out:
            status = "CRASH: ASan Heap OOB"
        else:
            status = "CRASH: ASan"
    elif "runtime error:" in out:
        status = "CRASH: UBSan"
    elif "RETURNED INVALID MODEL" in out:
        status = "RETURNED INVALID MODEL"
    elif "LoadModel SUCCESS" in out:
        status = "SUCCESS"
        
    print(f"{tname:<38} | {status}")

