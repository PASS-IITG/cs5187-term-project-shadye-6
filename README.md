# fastgltf Structure-Aware & Adaptive Hybrid Fuzzing — CS-5187 Term Project

[![Target: fastgltf v0.9.1](https://img.shields.io/badge/target-fastgltf_v0.9.1-blue.svg)](https://github.com/spnda/fastgltf)
[![Compiler: Clang 18.1.3](https://img.shields.io/badge/compiler-Clang_18.1.3-green.svg)](https://releases.llvm.org/18.1.3/)
[![Fuzzer: LLVM libFuzzer](https://img.shields.io/badge/fuzzer-libFuzzer_ASan_UBSan-red.svg)](https://llvm.org/docs/LibFuzzer.html)
[![Scheduler: Discounted UCB](https://img.shields.io/badge/scheduler-Discounted--UCB-orange.svg)](#)
[![Stopping: Conservative Saturation](https://img.shields.io/badge/saturation-6--State_Monitor-purple.svg)](#)

A security research project evaluating whether target-specific, structure-aware mutation coupled with dynamic multi-armed bandit scheduling (**Discounted-UCB**) and conservative saturation monitoring outperforms standard coverage-guided byte fuzzing on **fastgltf v0.9.1** (a high-performance C++17 glTF 2.0 parser).

---

## Repository Organization

```text
cs5187-term-project-shadye-6/
├── paper/    # The academic research report, in FSE (ACM acmsmall) LaTeX format
└── src/      # Full fuzzer code, mutators, schedulers, campaign supervisor, and reproducers
```

- **`src/` — Fuzzer Implementation & Evaluation:** Contains the complete fuzz targets, custom 4-way hybrid mutator, Discounted-UCB dynamic scheduler, in-memory provenance ledger, conservative saturation state machine, campaign supervisor, raw experimental logs, and vulnerability reproducers.  
  👉 **See [`src/README.md`](src/README.md) for full project architecture, mathematical formulation, build instructions, and reproduction steps.**
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
                                   v
                  +--------------------------------+
                  |    Discounted-UCB Scheduler    |
                  |  (Dynamic Multi-Armed Bandit)  |
                  +--------------------------------+
                                   |
         +-------------------------+-------------------------+
         |                                                   |
         v                                                   v
   [Byte Family]                                  [Structure-Aware Families]
   (floor: 5%)                                               |
                                      +----------------------+----------------------+
                                      |                      |                      |
                                      v                      v                      v
                                 [JSON AST]            [GLB Container]     [Procedural Generator]
                              (repair=true)          (Chunk Unpacking)       (gltf_generator)
                                      |                      |                      |
                                      +----------------------+----------------------+
                                                             |
                                                             v
                                                  [Invariant-Breaking]
                                                     (repair=false)
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
                                                                           [fastgltf::validate]
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
                                                                                    |
                                                                                    v
                                                                   [Single-Consumption Telemetry]
                                                                   [Attributed to Provenance Ledger]
                                                                                    |
                                                                                    v
                                                                   [Conservative Saturation Monitor]
                                                                   [6-State Plateau Controller]
```

### The 4 Experimental Modes:
1. **`fixed`:** Static baseline 25/25/40/10 family distribution without telemetry overhead.
2. **`adaptive`:** Dynamic Discounted-UCB scheduler updating weights between epochs.
3. **`fixed_with_saturation`:** Static baseline weights with conservative campaign saturation monitoring.
4. **`adaptive_with_saturation`:** Both Discounted-UCB adaptive scheduler and saturation monitor enabled.

---

## Quickstart: Build & Run

All commands are executed from the `src/` directory in a WSL2 Ubuntu or Linux environment:

```bash
cd src

# 1. Build all targets with AddressSanitizer and UndefinedBehaviorSanitizer
./scripts/build.sh asan

# 2. Run unit tests
cd build-asan && ./scheduler_tests && cd ..
python3 scripts/test_adaptive_fuzzer.py

# 3. Launch an adaptive campaign
python3 scripts/campaign_manager.py \
  --mode adaptive_with_saturation \
  --target deep_fuzzer \
  --output-dir findings/campaign_adaptive_sat \
  --epoch-seconds 300 \
  --hard-max-seconds 7200

# 4. Reproduce Novel Zero-Day F011 (Heap OOB Read in Parser::generateMeshIndices)
clang++ -std=c++17 -fsanitize=address,undefined -g -O0 \
  -Iexternal/fastgltf/include poc_f011.cpp \
  -Lbuild-asan/external/fastgltf -lfastgltf -o poc_f011
./poc_f011 findings/crashes/crash-db0170fae561bcc1186860580e462803e93ecac1
```

For the complete campaign driver, mathematical formulation, and crash deduplication pipeline, see [`src/README.md`](src/README.md).

---

## Term Project Graded Parts in `paper/`

| Part | Location | Description |
| :--- | :--- | :--- |
| **Motivating Example** | `paper/sections/introduction.tex` | Real F011 zero-day heap-buffer-overflow with exact numbers and trigger conditions. |
| **Workflow** | `paper/sections/approach.tex` | End-to-end architecture, Discounted-UCB scheduling, provenance ledger, and guarded buffer adapter. |
| **Research Questions** | `paper/sections/evaluation.tex` | Multi-arm empirical evaluation comparing fixed vs adaptive and saturation on/off. |
| **Related Work** | `paper/sections/related.tex` | Comparison against grammar-based fuzzing and general format mutators. |
| **Threats to Validity** | `paper/sections/threats.tex` | Internal, external, and construct threats (restart rate artifacts, template dedup). |
