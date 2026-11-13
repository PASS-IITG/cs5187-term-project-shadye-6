#!/usr/bin/env python3
import os, shutil, zipfile, glob

ROOT = "/mnt/c/Users/dxksh/Desktop/swa/raylib"
BUNDLE_DIR = f"{ROOT}/raylib_fuzzing_bundle"
ZIP_PATH = f"{ROOT}/raylib_fuzzing_results.zip"
REPORT_SRC = "/mnt/c/Users/dxksh/.gemini/antigravity/brain/3d35bdbd-56c4-4a6b-b762-26d7fa48f74a/fuzzing_postmortem_report.md"

if os.path.exists(BUNDLE_DIR):
    shutil.rmtree(BUNDLE_DIR)

os.makedirs(f"{BUNDLE_DIR}/reports", exist_ok=True)
os.makedirs(f"{BUNDLE_DIR}/logs", exist_ok=True)
os.makedirs(f"{BUNDLE_DIR}/reproducers", exist_ok=True)

# 1. Reports
if os.path.exists(REPORT_SRC):
    shutil.copy(REPORT_SRC, f"{BUNDLE_DIR}/reports/FUZZING_POSTMORTEM_REPORT.md")

# 2. Logs
for log in glob.glob(f"{ROOT}/work/logs/*.log"):
    shutil.copy(log, f"{BUNDLE_DIR}/logs/")

# 3. Curated Repro Files
targets = ["fuzz_audio_wav", "fuzz_automation", "fuzz_image_ops", "fuzz_model_gltf", "fuzz_render_vm", "fuzz_text"]

for t in targets:
    src_dir = f"{ROOT}/work/crashes/{t}"
    dst_dir = f"{BUNDLE_DIR}/reproducers/{t}"
    os.makedirs(dst_dir, exist_ok=True)
    if not os.path.exists(src_dir):
        continue
    
    files = [f for f in os.listdir(src_dir) if os.path.isfile(os.path.join(src_dir, f))]
    
    # Priority to files starting with crash-
    crash_files = [f for f in files if f.startswith("crash-")]
    other_files = [f for f in files if not f.startswith("crash-")]
    
    # Sort by size to pick minimal reproducers
    crash_files.sort(key=lambda f: os.path.getsize(os.path.join(src_dir, f)))
    other_files.sort(key=lambda f: os.path.getsize(os.path.join(src_dir, f)))
    
    # For small sets (<25), take all; for large sets, take top 25 smallest crashes + 5 others
    selected = crash_files[:25]
    if len(selected) < 25:
        selected += other_files[:(25 - len(selected))]
    
    for f in selected:
        shutil.copy(os.path.join(src_dir, f), os.path.join(dst_dir, f))

# 4. Create README and Reproduction Guide
readme_content = """# Raylib Fuzzing Results & Reproducer Bundle

This archive contains the final reports, campaign logs, and curated crash reproducers from the 4-hour parallel fuzzing campaign on `raylib` (commit `3b12ba1`).

## Directory Structure

- `reports/`:
  - `FUZZING_POSTMORTEM_REPORT.md`: Comprehensive post-mortem analysis detailing metrics, coverage, and the 6 vulnerability clusters.
  - `MAJOR_ISSUES.md`: Detailed technical breakdown of each major issue, root causes, file/line citations, and remediation steps.
- `logs/`:
  - Full AddressSanitizer and UndefinedBehaviorSanitizer execution logs for all 6 target binaries (`fuzz_audio_wav.log`, `fuzz_automation.log`, `fuzz_image_ops.log`, `fuzz_model_gltf.log`, `fuzz_render_vm.log`, `fuzz_text.log`).
- `reproducers/`:
  - Curated, minimized crashing test cases categorized by target:
    - `fuzz_model_gltf/`: glTF 2.0 accessor validation and NULL dereference crash artifacts.
    - `fuzz_render_vm/`: Software rasterizer matrix stack underflow and heap-buffer-overflow crash inputs.
    - `fuzz_automation/`: Automation replay (.rae) out-of-bounds intra-struct write crash inputs.
    - `fuzz_audio_wav/`: WAV loader NULL pointer dereference and chunk parsing crash artifacts.
    - `fuzz_image_ops/`: Image VM arithmetic exceptions, negative-size allocation, and buffer overflow inputs.
    - `fuzz_text/`: Font atlas generator heap over-read crash inputs.

## How to Reproduce

Each reproducer can be executed directly against the corresponding fuzzer binary or standalone harness:

```bash
# Example 1: Reproduce software rasterizer stack underflow crash
./out/libfuzzer/fuzz_render_vm reproducers/fuzz_render_vm/crash-...

# Example 2: Reproduce glTF loader attribute crash
./out/libfuzzer/fuzz_model_gltf reproducers/fuzz_model_gltf/crash-...

# Example 3: Reproduce automation replay out-of-bounds write
./out/libfuzzer/fuzz_automation reproducers/fuzz_automation/crash-...
```

ASan will immediately catch the memory safety violation and print the stack trace with symbolized line numbers.
"""

with open(f"{BUNDLE_DIR}/README.md", "w") as f:
    f.write(readme_content)

# 5. Create MAJOR_ISSUES.md
major_issues_content = """# Summary of Major Issues Found in Raylib (Commit 3b12ba1)

### 1. Software Rasterizer Matrix Stack Underflow
- **File & Line:** `src/external/rlsw.h:4379` in `swPopMatrix()`
- **Severity:** Very High (Memory Corruption / SEGV)
- **Description:** When `RLSW.stackModelviewCounter == 1`, the guard check `1 <= 0` passes. Evaluating `(--counter) - 1` computes index `-1` (`0xFFFFFFFF`), pointing `RLSW.currentMatrix` outside the `stackModelview[8]` array. The subsequent draw call writes directly into invalid memory.
- **Fix:** Update guard to check `if (RLSW.stackModelviewCounter < 2)`.

---

### 2. Untrusted Automation Event Replay Out-of-Bounds Memory Write
- **File & Line:** `src/rcore.c:3850` in `PlayAutomationEvent()`
- **Severity:** Very High (Arbitrary Intra-Struct Heap Write)
- **Description:** Parameters from untrusted `.rae` files are used directly as array indices into `CORE.Input.Gamepad.axisState[event.params[0]][event.params[1]]` and button arrays without bounds checks.
- **Fix:** Verify `event.params[0] < MAX_GAMEPADS` and `event.params[1] < MAX_GAMEPAD_AXES`.

---

### 3. Automation Event Type Global Buffer Over-Read
- **File & Line:** `src/rcore.c:3758` in `autoEventTypeName()`
- **Severity:** Major (Information Disclosure / Over-read)
- **Description:** `autoEventTypeName` indexes into `autoEventTypeNames[24]` using unvalidated `event.type`.
- **Fix:** Bound-check `event.type < 24` before indexing.

---

### 4. glTF Missing Buffer View Validation
- **File & Line:** `src/rmodels.c:5788` in `LoadGLTF()`
- **Severity:** Major (NULL Pointer Dereference / Heap Over-read)
- **Description:** Iterates glTF accessors and loads buffer views without verifying non-NULL status or buffer bounds.
- **Fix:** Call `cgltf_validate()` on parsed data.

---

### 5. Audio Frame Allocation Failure NULL Pointer Dereference
- **File & Line:** `src/raudio.c:1330–1337` in `LoadWaveSamples()`
- **Severity:** Medium (Denial of Service Crash)
- **Description:** When `RL_MALLOC` returns NULL on large allocations or integer overflows, the returned pointer is immediately dereferenced in the sample unpacking loop.
- **Fix:** Check `if (samples == NULL) return NULL;`.

---

### 6. Font Atlas Generation Heap Over-Read on 0 Glyphs
- **File & Line:** `src/rtext.c:284` in `GenImageFontAtlas()`
- **Severity:** Medium (Heap Buffer Over-read)
- **Description:** When an input file resolves 0 glyphs, the atlas generator defaults `glyphCount` to 95 and iterates past the unallocated glyph buffer.
- **Fix:** Validate `glyphCount > 0` before packing.
"""

with open(f"{BUNDLE_DIR}/reports/MAJOR_ISSUES.md", "w") as f:
    f.write(major_issues_content)

# 6. Compress into ZIP
print(f"Compressing bundle into {ZIP_PATH}...")
if os.path.exists(ZIP_PATH):
    os.remove(ZIP_PATH)

with zipfile.ZipFile(ZIP_PATH, 'w', zipfile.ZIP_DEFLATED) as zipf:
    for root, dirs, files in os.walk(BUNDLE_DIR):
        for file in files:
            file_path = os.path.join(root, file)
            arcname = os.path.relpath(file_path, BUNDLE_DIR)
            zipf.write(file_path, arcname)

size_mb = os.path.getsize(ZIP_PATH) / (1024 * 1024)
print(f"Successfully created {ZIP_PATH} ({size_mb:.2f} MB)")

