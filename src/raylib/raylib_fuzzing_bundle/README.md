# Raylib Fuzzing Results & Reproducer Bundle

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
