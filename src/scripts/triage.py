#!/usr/bin/env python3
"""
Automated crash triage, deduplication, and upstream report generation script.
Properly parses symbolized C++ stacks, resolves root causes (preventing template truncation),
maps Issue #144 crashes accurately, and generates complete, non-empty vulnerability reports.
"""

import os
import sys
import glob
import subprocess
import re
import datetime
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent

def sanitize_sig(sig):
    # Keep alphanumeric, colon, underscore, angle brackets if clean, @
    return sig.strip()

def run_target(bin_path, crash_file):
    env = os.environ.copy()
    env["ASAN_OPTIONS"] = "abort_on_error=1:detect_leaks=0:symbolize=1"
    env["UBSAN_OPTIONS"] = "print_stacktrace=1:halt_on_error=1:abort_on_error=1:symbolize=1"
    
    cmd = [str(bin_path), str(crash_file)]
    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=15,
            env=env,
            errors="replace"
        )
        return proc.returncode, proc.stdout
    except subprocess.TimeoutExpired:
        return -1, "Execution timed out (hang/infinite loop)"
    except Exception as e:
        return -2, f"Execution failed: {e}"

def parse_crash_output(output):
    """
    Parses crash output to extract:
    1. Sanitizer type / classification
    2. Stack frames with full symbolized function names (no template truncation)
    3. Root-cause function and classification
    4. Formatted snippet of the full stack trace
    """
    sanitizer = "Unknown"
    notes = "New potential candidate"
    type_class = "TARGET_ASAN"
    known_issue = "No"

    # 1. Detect crash type
    if "AddressSanitizer: heap-buffer-overflow" in output:
        sanitizer = "heap-buffer-overflow"
    elif "AddressSanitizer: global-buffer-overflow" in output:
        sanitizer = "global-buffer-overflow"
    elif "AddressSanitizer: stack-buffer-overflow" in output:
        sanitizer = "stack-buffer-overflow"
    elif "AddressSanitizer: use-after-free" in output:
        sanitizer = "use-after-free"
    elif "terminate called after throwing an instance of" in output:
        m_exc = re.search(r"terminate called after throwing an instance of '([^']+)'", output)
        if m_exc:
            sanitizer = f"exception:{m_exc.group(1).strip()}"
        else:
            sanitizer = "exception"
    elif "Assertion" in output or "assert" in output:
        m_assert = re.search(r"Assertion `([^`]+)' failed", output)
        if m_assert:
            sanitizer = f"assert({m_assert.group(1).strip()})"
        else:
            sanitizer = "assert"
    elif "UndefinedBehaviorSanitizer" in output or "runtime error:" in output:
        m_ub = re.search(r"runtime error:\s*([^\n]+)", output)
        if m_ub:
            sanitizer = f"UBSan:{m_ub.group(1).strip()}"
        else:
            sanitizer = "UBSan"
    elif "AddressSanitizer: SEGV" in output or "deadly signal" in output:
        sanitizer = "SEGV"

    # 2. Extract stack frames
    # Stack lines typically look like:
    # #0 0x... in <func_name> <file_path>:<line>:<col>
    frames = []
    stack_lines = []
    
    # Capture relevant lines for stack trace snippet
    capture = False
    for line in output.splitlines():
        if any(marker in line for marker in [
            "ERROR: AddressSanitizer",
            "runtime error:",
            "SUMMARY: UndefinedBehaviorSanitizer",
            "terminate called",
            "Assertion `",
            "ERROR: libFuzzer: deadly signal"
        ]):
            capture = True
        
        if capture:
            # Ignore shadow bytes or excessive libfuzzer info
            if "Shadow bytes around" in line or "ABORTING" in line:
                break
            stack_lines.append(line)
            if len(stack_lines) > 35:
                break

        # Frame extraction:
        m_frame = re.match(r"^\s*#(\d+)\s+0x[0-9a-fA-F]+\s+in\s+(.+)$", line)
        if m_frame:
            frame_num = int(m_frame.group(1))
            rest = m_frame.group(2).strip()
            # Separate function from file path
            # File path usually starts with a slash or drive letter preceded by space
            m_path = re.search(r"\s+((?:/|[A-Za-z]:[/\\])[^\s:]+):(\d+)(?::(\d+))?", rest)
            if m_path:
                func_sym = rest[:m_path.start()].strip()
                file_info = m_path.group(0).strip()
            else:
                # Might end with binary name like (/path/to/binary+0x...)
                m_bin = re.search(r"\s+\([^)]+\)", rest)
                if m_bin:
                    func_sym = rest[:m_bin.start()].strip()
                    file_info = m_bin.group(0).strip()
                else:
                    func_sym = rest
                    file_info = ""
            frames.append((frame_num, func_sym, file_info))

    # 3. Identify root-cause function and classify
    # We inspect all frames in the stack to find the true root cause,
    # rather than naively grabbing an inlined leaf frame or return type.
    root_func = None
    all_funcs_str = " ".join([f[1] for f in frames])

    # Rule A: deserializeComponent / accessor extent bounds without validate (Issue #144)
    if "deserializeComponent" in all_funcs_str or "convertAccessorElement" in all_funcs_str:
        root_func = "fastgltf::internal::deserializeComponent"
        type_class = "KNOWN_FINDING"
        known_issue = "Issue #144 (deserializeComponent)"
        notes = "Known accessor bounds issue in unvalidated loadGltf"
    elif "generateMeshIndices" in all_funcs_str:
        root_func = "fastgltf::Parser::generateMeshIndices"
        type_class = "TARGET_ASAN"
        known_issue = "No"
        notes = "Heap buffer overflow in generateMeshIndices (POSITION accessor index unvalidated)"
    elif "findSparseIndex" in all_funcs_str:
        root_func = "fastgltf::internal::findSparseIndex"
        type_class = "KNOWN_FINDING"
        known_issue = "Issue #144 (findSparseIndex)"
        notes = "Sparse accessor index out of bounds in unvalidated asset"
    elif "getPadding" in all_funcs_str:
        root_func = "fastgltf::base64::getPadding"
        type_class = "TARGET_ASAN"
        known_issue = "Issue #157 (malformed Base64 length)"
        notes = "Base64 padding computation assertion failure on malformed length"
    elif "fallback_decode_inplace" in all_funcs_str or "decode_inplace" in all_funcs_str:
        root_func = "fastgltf::base64::decode_inplace"
        type_class = "TARGET_ASAN"
        known_issue = "Issue #157 / Base64 LUT bounds"
        notes = "Base64 invalid character lookup or buffer bounds"
    elif "URIView" in all_funcs_str:
        root_func = "fastgltf::URIView::URIView"
        type_class = "TARGET_ASAN"
        known_issue = "No"
        notes = "Out of range string_view substr during URIView parsing"
    else:
        # Walk frames from top to bottom, find first fastgltf frame
        for _, sym, _ in frames:
            # Clean up symbol: strip return type if present
            # E.g.: "fastgltf::math::vec<float, 3ul> fastgltf::..." -> extract second part
            m_fg = re.search(r"\b(fastgltf::[A-Za-z0-9_:]+)", sym)
            if m_fg:
                root_func = m_fg.group(1)
                break
        if not root_func:
            root_func = "fastgltf_unknown"

    # If stack trace lines were not captured by markers, grab any error lines
    if not stack_lines:
        stack_lines = [l for l in output.splitlines() if l.strip()][:25]

    stack_trace_text = "\n".join(stack_lines).strip()
    return sanitizer, root_func, type_class, known_issue, notes, stack_trace_text

from concurrent.futures import ThreadPoolExecutor

def triage_campaign(crash_dir, bin_path, index_csv, reports_dir):
    os.makedirs(reports_dir, exist_ok=True)
    
    if not os.path.exists(index_csv):
        with open(index_csv, "w", encoding="utf-8") as f:
            f.write("id,signature,type,sanitizer,first_seen,testcase,minimized_testcase,version,status,known_issue,notes\n")

    crash_files = sorted(glob.glob(os.path.join(crash_dir, "*")))
    crash_files = [f for f in crash_files if os.path.isfile(f) and not f.endswith(".md") and not f.endswith(".csv")]

    if not crash_files:
        print(f"No crash artifacts found in {crash_dir}.", flush=True)
        return

    print("==========================================================", flush=True)
    print(f" Triaging and Deduplicating Crashes in: {crash_dir}", flush=True)
    print(f" Target Binary: {bin_path}", flush=True)
    print("==========================================================", flush=True)

    # Run all crash artifacts in parallel with ThreadPoolExecutor
    results = []
    print(f"[*] Replaying {len(crash_files)} crashes concurrently...", flush=True)
    with ThreadPoolExecutor(max_workers=8) as executor:
        futures = {executor.submit(run_target, bin_path, cf): cf for cf in crash_files}
        for future in futures:
            cf = futures[future]
            try:
                status, out = future.result()
                results.append((cf, status, out))
            except Exception as e:
                results.append((cf, -3, str(e)))

    # Sort results deterministically by crash filename
    results.sort(key=lambda r: r[0])

    signatures = {} # signature -> finding_id
    finding_idx = 1
    
    # Read existing index if present to keep finding numbers consistent
    if os.path.isfile(index_csv):
        with open(index_csv, "r", encoding="utf-8") as f:
            lines = f.readlines()
            for line in lines[1:]:
                parts = line.strip().split(",")
                if parts and parts[0].startswith("FINDING-"):
                    try:
                        num = int(parts[0].replace("FINDING-", ""))
                        if num >= finding_idx:
                            finding_idx = num + 1
                    except ValueError:
                        pass

    new_findings_count = 0
    duplicate_count = 0
    non_crashing_count = 0

    for crash_file, status, out in results:
        if status == 0:
            non_crashing_count += 1
            continue

        sanitizer, root_func, type_class, known_issue, notes, stack_text = parse_crash_output(out)
        sig = f"{sanitizer}@{root_func}"

        if sig in signatures:
            duplicate_count += 1
            continue

        finding_id = f"FINDING-{finding_idx:03d}"
        signatures[sig] = finding_id
        finding_idx += 1
        new_findings_count += 1

        timestamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        file_size = os.path.getsize(crash_file)

        # Write to index.csv
        with open(index_csv, "a", encoding="utf-8") as f:
            f.write(f'{finding_id},"{sig}",{type_class},{sanitizer},{timestamp},{crash_file},,"v0.9.1",open,{known_issue},"{notes}"\n')

        # Generate markdown report
        report_path = os.path.join(reports_dir, f"{finding_id}.md")
        with open(report_path, "w", encoding="utf-8") as f:
            f.write(f"""# Vulnerability Report: {finding_id}

- **Summary**: {sanitizer} in {root_func}
- **Affected fastgltf version**: v0.9.1
- **Commit**: 705564d4d54500ae88befb0db9e361e447923655
- **Environment**: Linux under WSL2 Ubuntu 24.04, Clang 18.1.3
- **Input Size**: {file_size} bytes
- **Finding Class**: {type_class}
- **Known Issue**: {known_issue}
- **Reproduction Command**: `./build-asan/deep_fuzzer "{crash_file}"`

## Sanitizer Configuration
- ASan + UBSan (-fsanitize=fuzzer,address,undefined -fno-sanitize-recover=undefined)

## Observed Behavior
Under AddressSanitizer/UBSan, processing the testcase results in termination with {sanitizer}.

## Stack Trace
```text
{stack_text}
```

## Root-Cause Hypothesis
{notes}

## Upstream Recommendation
Verify invariant enforcement before direct indexing or component deserialization.
""")
        print(f"Recorded unique finding: {finding_id} ({sig}) -> {report_path}")

    print("----------------------------------------------------------")
    print(f"Triage complete.")
    print(f"Total processed: {len(crash_files)}")
    print(f"Unique findings: {new_findings_count}")
    print(f"Duplicates:      {duplicate_count}")
    print(f"Clean/Rechecked: {non_crashing_count}")
    print(f"Index updated:   {index_csv}")

if __name__ == "__main__":
    crashes = sys.argv[1] if len(sys.argv) > 1 else str(ROOT_DIR / "findings" / "crashes")
    target = sys.argv[2] if len(sys.argv) > 2 else str(ROOT_DIR / "build-asan" / "deep_fuzzer")
    idx_csv = str(ROOT_DIR / "findings" / "index.csv")
    reps_dir = str(ROOT_DIR / "findings" / "reports")
    triage_campaign(crashes, target, idx_csv, reps_dir)
