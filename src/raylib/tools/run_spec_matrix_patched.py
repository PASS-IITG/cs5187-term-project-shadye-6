import os, glob, subprocess

TEST_DIR = "/tmp/gltf_spec_tests"
BIN_PATCHED = "/tmp/test_raylib_importer"

test_files = sorted(glob.glob(f"{TEST_DIR}/*.gltf"))
print(f"{'Test Case':<38} | {'Patched Behavior':<22} | {'Sanitizer Status'}")
print("-" * 80)

env = dict(os.environ,
           ASAN_OPTIONS="abort_on_error=0:symbolize=1",
           UBSAN_OPTIONS="print_stacktrace=1:halt_on_error=0")

for tf in test_files:
    tname = os.path.basename(tf).replace(".gltf", "")
    p = subprocess.run([BIN_PATCHED, tf], env=env, capture_output=True, text=True, errors="replace")
    out = p.stdout + "\n" + p.stderr
    
    status = "OK"
    san = "Clean (0 errors)"
    if "ERROR: AddressSanitizer:" in out:
        if "SEGV" in out:
            addr = [l for l in out.splitlines() if "SEGV on" in l]
            san = f"CRASH: ASan SEGV ({addr[0].split('SEGV on')[1].split()[0] if addr else ''})"
        elif "heap-buffer-overflow" in out:
            san = "CRASH: ASan Heap OOB"
        else:
            san = "CRASH: ASan"
    elif "runtime error:" in out:
        san = "CRASH: UBSan"
        
    if "RETURNED INVALID MODEL" in out:
        status = "REJECTED SAFELY"
    elif "LoadModel SUCCESS" in out:
        status = "LOADED CLEANLY"
        
    print(f"{tname:<38} | {status:<22} | {san}")

