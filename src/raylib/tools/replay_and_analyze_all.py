#!/usr/bin/env python3
import os, glob, struct, subprocess, json

ROOT = "/mnt/c/Users/dxksh/Desktop/swa/raylib"
CRASH_DIR = f"{ROOT}/work/crashes/fuzz_model_gltf"
REPRO_BIN = f"{ROOT}/out/repro/fuzz_model_gltf"
ANALYZER = "/tmp/cgltf_analyzer"
TMP_DIR = "/tmp/gltf_repros"
REPORT_OUT = f"{ROOT}/work/gltf_replay_report.txt"

os.makedirs(TMP_DIR, exist_ok=True)
crashes = sorted(glob.glob(f"{CRASH_DIR}/crash-*"))

out_lines = []
def log(s=""):
    out_lines.append(str(s))

log(f"Total glTF crash files found: {len(crashes)}\n")

for i, cp in enumerate(crashes, 1):
    cname = os.path.basename(cp)
    log("="*80)
    log(f"CRASH #{i}: {cname}")
    log("="*80)
    
    out_dir = f"{TMP_DIR}/{cname}"
    os.makedirs(out_dir, exist_ok=True)
    raw = open(cp, "rb").read()
    pos = 0
    file_idx = 0
    main_file = None
    
    while pos < len(raw):
        namelen = raw[pos]
        pos += 1
        if pos + namelen > len(raw): break
        fname = raw[pos:pos+namelen].decode("latin1", errors="replace")
        pos += namelen
        if pos + 4 > len(raw): break
        flen = struct.unpack("<I", raw[pos:pos+4])[0]
        pos += 4
        fdata = raw[pos:pos+flen]
        pos += flen
        if file_idx == 0:
            main_file = fname
        safe_name = os.path.basename(fname) if os.path.basename(fname) else f"file_{file_idx}"
        target_path = os.path.join(out_dir, safe_name)
        with open(target_path, "wb") as f:
            f.write(fdata)
        log(f"  Unpacked: {fname} -> {safe_name} ({len(fdata)} bytes)")
        file_idx += 1
        
    env = dict(os.environ, FUZZ_KNOWN="1",
               ASAN_OPTIONS="abort_on_error=0:symbolize=1",
               UBSAN_OPTIONS="print_stacktrace=1:halt_on_error=0")
    
    p = subprocess.run([REPRO_BIN, cp], env=env, capture_output=True, text=True, errors="replace")
    stdout_stderr = p.stdout + "\n" + p.stderr
    
    log("\n--- [A] Sanitizer Traces & Exact Source Line ---")
    for l in stdout_stderr.splitlines():
        if "runtime error:" in l or "SUMMARY: UndefinedBehaviorSanitizer:" in l:
            log(f"  UBSan: {l.strip()}")
        if "ERROR: AddressSanitizer:" in l or "SUMMARY: AddressSanitizer:" in l:
            log(f"  ASan:  {l.strip()}")
        if "Hint:" in l:
            log(f"  Hint:  {l.strip()}")
            
    rmodels_frames = [l for l in stdout_stderr.splitlines() if "rmodels.c:" in l and ("#" in l or "runtime error:" in l)]
    for rf in rmodels_frames[:3]:
        log(f"  Frame: {rf.strip()}")
        
    log("\n--- [B] cgltf Parse / Load / Validate Check ---")
    main_path = os.path.join(out_dir, "main.gltf")
    if not os.path.exists(main_path):
        gltfs = glob.glob(f"{out_dir}/*.gltf")
        main_path = gltfs[0] if gltfs else None
        
    if main_path and os.path.exists(main_path):
        p_an = subprocess.run([ANALYZER, main_path], cwd=out_dir, capture_output=True, text=True, errors="replace")
        for line in p_an.stdout.splitlines():
            if any(k in line for k in ["cgltf_", "Accessor #", "buffer_view:", "is_sparse:", "Attr #", "count:"]):
                log(f"  {line}")
                
        try:
            with open(main_path, "r", errors="ignore") as f:
                j = json.load(f)
                accessors = j.get("accessors", [])
                log(f"\n--- [C] JSON Accessors Analysis ({len(accessors)} accessors) ---")
                for a_i, acc in enumerate(accessors):
                    has_bv = "bufferView" in acc
                    has_sparse = "sparse" in acc
                    log(f"  Accessor #{a_i}: count={acc.get('count')}, type={acc.get('type')}, componentType={acc.get('componentType')}, bufferView={'YES (' + str(acc.get('bufferView')) + ')' if has_bv else 'MISSING'}, sparse={'YES' if has_sparse else 'NO'}")
        except Exception as e:
            log(f"  JSON parse error: {e}")
    else:
        log(f"  No .gltf file found in {out_dir}")
        
    log("\n")

with open(REPORT_OUT, "w") as f:
    f.write("\n".join(out_lines))

print(f"Report written to {REPORT_OUT}")
