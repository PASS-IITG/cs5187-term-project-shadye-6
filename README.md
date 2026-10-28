# fastgltf Structure-Aware Fuzzing — CS-5187 Term Project

[![Target: fastgltf v0.9.1](https://img.shields.io/badge/target-fastgltf_v0.9.1-blue.svg)](https://github.com/spnda/fastgltf)
[![Compiler: Clang 18.1.3](https://img.shields.io/badge/compiler-Clang_18.1.3-green.svg)](https://releases.llvm.org/18.1.3/)
[![Fuzzer: LLVM libFuzzer](https://img.shields.io/badge/fuzzer-libFuzzer_ASan_UBSan-red.svg)](https://llvm.org/docs/LibFuzzer.html)

A security research project evaluating whether target-specific, structure-aware mutation outperforms standard coverage-guided byte fuzzing on **fastgltf v0.9.1** (a high-performance C++17 glTF 2.0 parser).

---

## Repository Organization

```text
cs5187-term-project-shadye-6/
├── paper/    # The academic research report, in FSE (ACM acmsmall) LaTeX format
└── src/      # Full fuzzer code, mutators, safety oracles, campaign data, and reproducers
```

- **`src/` — Fuzzer Implementation & Evaluation:** Contains the complete fuzz targets, custom 4-way hybrid mutator, GLB chunk handler, safety oracles, campaign scripts, raw experimental logs, and vulnerability reproducers.  
  👉 **See [`src/README.md`](src/README.md) for full project architecture, build instructions, and reproduction steps.**
- **`paper/` — FSE Research Report:** The academic paper written in ACM FSE (`acmsmall`) LaTeX format. Run `cd paper && make` to build `main.pdf` and `make check` to verify formatting and constraints.

---

## Project Architecture Overview

```text
                  +--------------------------------+
                  |    Seed Corpus (corpus/seed)   |
                  +--------------------------------+
                                   |
                                   v
                  +--------------------------------+
                  |           libFuzzer            |
                  +--------------------------------+
                                   |
         +-------------------------+-------------------------+
         |                                                   |
         v                                                   v
   [Byte Mutation]                                [Structure-Aware Mutation]
   (25% Fallback)                                            |
                                      +----------------------+----------------------+
                                      |                      |                      |
                                      v                      v                      v
                                 [JSON AST]            [GLB Container]     [Procedural Generator]
                               (repair=true 25%)      (Chunk Unpacking)        (Scratch 10%)
                                      |                      |                      |
                                      +----------------------+----------------------+
                                                             |
                                                             v
                                                  [Cross-Field Invariants]
                                                     (repair=false 40%)
                                                             |
                                                             v
                                               [Fuzzer Envelope Stream]
                                               [profile_byte][payload...]
                                                             |
                                                             v
                                                  [fastgltf::Parser]
                                                             |
                                      +----------------------+----------------------+
                                      |                                             |
                                      v                                             v
                              [Parse Rejection]                               [Loaded Asset]
                                                                                    |
                                                                                    v
                                                                           [exerciseAsset]
                                                                        (Bounded Traversal)
                                                                                    |
                                                                  +-----------------+-----------------+
                                                                  |                                   |
                                                                  v                                   v
                                                        [DefaultBufferAdapter]             [GuardedBufferAdapter]
                                                                  |                       (ASan Redzone Alloc)
                                                                  +-----------------+-----------------+
                                                                                    |
                                                                                    v
                                                                    [ASan / UBSan / Invariant Check]
```

### Key Fuzzing Targets:
- **`deep_fuzzer`:** Primary deep target exercising envelope profile decoding, `Parser::loadGltf()`, and accessor traversal with guarded memory adapters.
- **`parser_fuzzer`:** Baseline target exercising pure parser throughput without downstream accessor traversal.
- **`uri_fuzzer`:** Micro-target focusing on `fastgltf::URIView` RFC parsing, authorities, and percent-decoding.
- **`base64_fuzzer`:** Micro-target evaluating AVX2 SIMD vs fallback base64 decoders.

---

## Quickstart: Build & Run

All commands are run from the `src/` directory in a WSL2 Ubuntu or Linux environment:

```bash
cd src

# 1. Build all targets with AddressSanitizer and UndefinedBehaviorSanitizer
./scripts/build.sh asan

# 2. Run a 10-minute hybrid fuzzing session
./scripts/fuzz.sh --target deep_fuzzer --mode hybrid --time 600

# 3. Reproduce Novel Zero-Day F011 (Heap OOB Read in Parser::generateMeshIndices)
clang++ -std=c++17 -fsanitize=address,undefined -g -O0 \
  -Iexternal/fastgltf/include poc_f011.cpp \
  -Lbuild-asan/external/fastgltf -lfastgltf -o poc_f011
./poc_f011 findings/crashes/crash-db0170fae561bcc1186860580e462803e93ecac1
```

For the complete campaign driver, code coverage generation, and crash deduplication pipeline, see [`src/README.md`](src/README.md).

---

## Term Project Graded Parts in `paper/`

| Part | Location | Description |
| :--- | :--- | :--- |
| **Motivating Example** | `paper/sections/introduction.tex` | Real F011 zero-day heap-buffer-overflow with exact numbers and trigger conditions. |
| **Workflow** | `paper/sections/approach.tex` | End-to-end architecture, 4-way hybrid mutation split, and guarded buffer adapter. |
| **Research Questions** | `paper/sections/evaluation.tex` | Multi-arm empirical evaluation (15 trials) measuring coverage and execution rates. |
| **Related Work** | `paper/sections/related.tex` | Comparison against grammar-based fuzzing and general format mutators. |
| **Threats to Validity** | `paper/sections/threats.tex` | Internal, external, and construct threats (restart rate artifacts, template dedup). |
