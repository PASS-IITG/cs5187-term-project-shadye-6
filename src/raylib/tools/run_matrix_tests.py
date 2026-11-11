#!/usr/bin/env python3
import os, glob, subprocess

TEST_DIR = "/tmp/gltf_spec_tests"
CGLTF_BIN = "/tmp/cgltf_analyzer"
RAYLIB_BIN = "/tmp/test_raylib_importer"

test_files = sorted(glob.glob(f"{TEST_DIR}/*.gltf"))

print(f"{'Test Case':<36} | {'cgltf_parse':<12} | {'cgltf_load':<12} | {'cgltf_val':<10} | {'raylib Importer Result'}")
print("-" * 110)

env = dict(os.environ,
           ASAN_OPTIONS="abort_on_error=0:symbolize=1",
           UBSAN_OPTIONS="print_stacktrace=1:halt_on_error=0")

for tf in test_files:
    tname = os.path.basename(tf).replace(".gltf", "")
    
    # 1. Run cgltf test
    p_cg = subprocess.run([CGLTF_BIN, tf], capture_output=True, text=True, errors="replace")
    cg_out = p_cg.stdout
    
    p_parse = "SUCCESS" if "cgltf_parse_file: SUCCESS" in cg_out else "FAILED"
    p_load = "SUCCESS" if "cgltf_load_buffers: SUCCESS" in cg_out else "FAILED"
    p_val = "SUCCESS" if "cgltf_validate: SUCCESS" in cg_out else "FAILED"
    
    # 2. Run raylib test
    p_rl = subprocess.run([RAYLIB_BIN, tf], env=env, capture_output=True, text=True, errors="replace")
    rl_out = p_rl.stdout + "\n" + p_rl.stderr
    
    rl_res = "SUCCESS"
    if "ERROR: AddressSanitizer:" in rl_out:
        if "SEGV" in rl_out:
            rl_res = "CRASH (ASan SEGV)"
        elif "heap-buffer-overflow" in rl_out:
            rl_res = "CRASH (ASan Heap OOB)"
        else:
            rl_res = "CRASH (ASan)"
    elif "runtime error:" in rl_out:
        if "null pointer" in rl_out:
            rl_res = "CRASH (UBSan NULL deref)"
        else:
            rl_res = "CRASH (UBSan)"
    elif p_rl.returncode != 0:
        rl_res = f"FAILED (rc={p_rl.returncode})"
    elif "RETURNED INVALID MODEL" in rl_out:
        rl_res = "REJECTED SAFELY"
        
    print(f"{tname:<36} | {p_parse:<12} | {p_load:<12} | {p_val:<10} | {rl_res}")

