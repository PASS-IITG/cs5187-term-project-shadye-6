# Vulnerability Report: FINDING-012

- **Summary**: UBSan in fastgltf_unknown
- **Affected fastgltf version**: v0.9.1
- **Commit**: 705564d4d54500ae88befb0db9e361e447923655
- **Environment**: Linux under WSL2 Ubuntu 24.04, Clang 18.1.3
- **Input Size**: 241 bytes
- **Finding Class**: TARGET_ASAN
- **Known Issue**: No
- **Reproduction Command**: `./build-asan/deep_fuzzer "/mnt/c/Users/dxksh/Desktop/swa/fastgltf/findings/crashes/crash-f22a4d3af933ecfaa9924b7b0d512d1f7275ed07"`

## Sanitizer Configuration
- ASan + UBSan (-fsanitize=fuzzer,address,undefined -fno-sanitize-recover=undefined)

## Observed Behavior
Under AddressSanitizer/UBSan, processing the testcase results in termination with UBSan.

## Stack Trace
```text
SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior /mnt/c/Users/dxksh/Desktop/swa/fastgltf/external/fastgltf/include/fastgltf/types.hpp:1808:11 
```

## Root-Cause Hypothesis
New potential candidate

## Upstream Recommendation
Verify invariant enforcement before direct byte indexing in accessor tools.
