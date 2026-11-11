# Cross-Domain Fuzzing Through Structure-Aware Mutation and Bandit-Guided Adaptation

[![Course: CS-5187](https://img.shields.io/badge/course-CS--5187_Term_Project-blue.svg)](https://www.iitg.ac.in/)
[![Institution: IIT Guwahati](https://img.shields.io/badge/institution-IIT_Guwahati-maroon.svg)](https://www.iitg.ac.in/)
[![Tool: QTFuzz](https://img.shields.io/badge/tool-QTFuzz_v1.0-orange.svg)](#)
[![Compiler: Clang 18.1.3](https://img.shields.io/badge/compiler-Clang_18.1.3-green.svg)](https://releases.llvm.org/18.1.3/)
[![Sanitizers: ASan + UBSan](https://img.shields.io/badge/sanitizers-ASan_+_UBSan-red.svg)](https://llvm.org/docs/AddressSanitizer.html)
[![Executions: 807M+](https://img.shields.io/badge/executions-807M+_across_59_targets-brightgreen.svg)](#)
[![Vulnerabilities: 16 Discovered](https://img.shields.io/badge/vulnerabilities-16_discovered_(6_upstream)-critical.svg)](#security-vulnerabilities--discovered-defects)
[![Paper: ACM FSE acmsmall](https://img.shields.io/badge/paper-ACM_acmsmall_(12_pages)-blueviolet.svg)](paper/main.pdf)

> **Authors:** Dakshin, Neel, Samyak  
> **Department of Computer Science and Engineering, Indian Institute of Technology Guwahati**  
> **Paper Title:** *Cross-Domain Fuzzing Through Structure-Aware Mutation and Bandit-Guided Adaptation*  
> **Target Frameworks:** `fastgltf` (3D Parser), `raylib` (Multimedia Engine), `drogon` (Async Web Server)  
> **Research Paper (PDF):** 📄 **[`paper/main.pdf`](paper/main.pdf)** (12-page ACM FSE formatted PDF)

---

## Executive Summary

Coverage-guided greybox fuzzers like AFL++ and libFuzzer traditionally treat test inputs as opaque byte sequences. While effective for simple binary formats, this byte-level abstraction suffers from severe **domain impedance mismatches** when applied across heterogeneous, real-world software ecosystems:
1. **Hierarchical 3D File Formats (`fastgltf`):** Interleaved JSON metadata and binary geometry buffers cause raw byte mutators to saturate early on shallow syntax checks.
2. **Interactive Multimedia & Game Engines (`raylib`):** Systems that require active display servers, hardware framebuffers, and audio mixing hardware, preventing automated execution in headless test runners.
3. **Asynchronous Web Frameworks (`drogon`):** Multi-threaded servers bound to operating system TCP/IP loopback sockets, capping execution throughput to hundreds of iterations per second.

**QTFuzz** is a cross-domain fuzzing architecture engineered to bridge these gaps without sacrificing execution speed. By combining **domain-specific structure-aware mutators**, **zero-socket in-memory network mocks**, **headless software rasterizer shims**, and an adaptive **multi-armed bandit (Discounted-UCB / UCB1) scheduler**, QTFuzz achieved **over 807 million executions across 59 target binaries**, discovering **16 critical and high-severity security defects**, with **6 vulnerabilities acknowledged, merged, or fixed upstream** by maintainers.

---

## Architecture Overview

```text
                                  +----------------------------------+
                                  |     Domain Seed Corpus Pool      |
                                  +----------------------------------+
                                                   |
                                                   v
                                  +----------------------------------+
                                  |    Multi-Armed Bandit (MAB)      |
                                  |    Discounted-UCB1 / UCB1        |
                                  +----------------------------------+
                                                   |
                   +-------------------------------+-------------------------------+
                   |                               |                               |
                   v                               v                               v
    +------------------------------+ +------------------------------+ +------------------------------+
    |   Domain 1: 3D AST / glTF    | |  Domain 2: Headless Media    | |   Domain 3: Async Web Server   |
    |          fastgltf            | |            raylib            | |            drogon            |
    +------------------------------+ +------------------------------+ +------------------------------+
    | * Structure-aware JSON AST   | | * 37 isolated target shims   | | * MockTcpConnection in memory|
    | * Binary chunk byte fixup    | | * Software rasterizer (rlsw) | | * Zero OS socket loopback    |
    | * GuardedBufferAdapter (ASan)| | * Deterministic audio pump   | | * Tail-scheduled slicing     |
    | * Bounded accessor walker    | | * Linker symbol wrapping     | | * RAII upload directory sand-|
    | * Procedural generator       | | * Capped allocator shims     | |   box isolation              |
    +------------------------------+ +------------------------------+ +------------------------------+
                   |                               |                               |
                   v                               v                               v
    [3 Target Fuzz Harnesses]      [37 Decoupled Harnesses]        [19 In-Memory Web Harnesses]
    Peak: 145 exec/s               Peak: 8,920 exec/s              Peak: 53,732 exec/s
                   |                               |                               |
                   +-------------------------------+-------------------------------+
                                                   |
                                                   v
                                  +----------------------------------+
                                  |  Sanitizers & Safety Oracles     |
                                  |  (AddressSanitizer + UBSan)      |
                                  +----------------------------------+
                                                   |
                   +-------------------------------+-------------------------------+
                   |                                                               |
                   v                                                               v
    +------------------------------+                                +------------------------------+
    |   Per-Input Telemetry Ledger |                                | Conservative Saturation      |
    |   Attributed Reward to MAB   |                                | 6-State Plateau Controller   |
    +------------------------------+                                +------------------------------+
```

---

## Subject Systems & Campaign Scale

Over a combined 24-hour campaign on an x86_64 AMD workstation (16 logical cores, Ubuntu 24.04 LTS), QTFuzz executed **807,520,128 cumulative inputs**:

| Subject System | Target Domain | Version / Commit | LoC | Targets | Total Executions | Peak Throughput | Discovered Edges |
| :--- | :--- | :--- | :---: | :---: | :---: | :---: | :---: |
| **`fastgltf`** | 3D Asset / glTF Parser | v0.9.1 (`705564d`) | 14,280 | 3 | 3,200,000 | 145 exec/s | 4,218 |
| **`raylib`** | Game & Multimedia Engine | master (`e1a4079`) | 118,940 | 37 | 54,320,128 | 8,920 exec/s | 47,121 |
| **`drogon`** | Asynchronous Web Server | v1.9.8 (`df418bf`) | 68,410 | 19 | 750,000,000 | 53,732 exec/s | 3,178 |
| **Total** | — | — | **201,630** | **59** | **807,520,128** | **53,732 exec/s** | — |

---

## Security Vulnerabilities & Discovered Defects

### 1. Verified Upstream Vulnerabilities (Acknowledged / Merged / Fixed)

| ID | Subject | Component | Vulnerability Class | CWE | Upstream Issue / PR | Resolution Status |
| :---: | :--- | :--- | :--- | :---: | :--- | :--- |
| **F1** | `fastgltf` | `generateMeshIndices` | Heap Buffer Overflow | CWE-122 | [Issue #160](https://github.com/spnda/fastgltf/issues/160) | **Closed**; fixed via maintainer commit |
| **R1** | `raylib` | `swPopMatrix()` in `rlsw.h` | Matrix Stack Underflow | CWE-119 | [Issue #6361](https://github.com/raysan5/raylib/issues/6361) / [PR #6362](https://github.com/raysan5/raylib/pull/6362) | **Acknowledged**; PR #6362 merged upstream |
| **R2** | `raylib` | `ExportAutomationEventList()` | Out-of-Bounds Heap Read | CWE-125 | [Issue #6378](https://github.com/raysan5/raylib/issues/6378) | **Acknowledged**; fixed via maintainer commit |
| **R3** | `raylib` | `LoadWaveSamples()` | NULL Pointer Dereference | CWE-476 | [Issue #6373](https://github.com/raysan5/raylib/issues/6373) / [Commit 7639166](https://github.com/raysan5/raylib/commit/7639166019f6d300435a2610726150558f745bee) | **Acknowledged**; fixed alternatively by maintainer |
| **D1** | `drogon` | `HttpFileImpl::save()` | Process Abort in `noexcept` | CWE-755 | [Issue #2661](https://github.com/drogonframework/drogon/issues/2661) / [PR #2662](https://github.com/drogonframework/drogon/pull/2662) | **Closed**; PR #2662 merged upstream |
| **D2** | `drogon` | `HttpFileImpl::save()` | Iterator Out-of-Bounds | CWE-125 | [PR #2656](https://github.com/drogonframework/drogon/pull/2656) | **Closed**; issue raised, fixed in commit by maintainer |

### 2. Additional Unfiled Security Defects (Medium / High / Critical)

In addition to the 6 upstream-verified vulnerabilities above, QTFuzz uncovered 10 high-impact defects in `raylib` and `drogon`:

| Subject | Component | Defect Type | Severity | Impact Description |
| :--- | :--- | :--- | :---: | :--- |
| `raylib` | `UpdateModelAnimationBones` | Heap Buffer Overflow | **Critical** | Arbitrary heap write via unvalidated bone transform counts (`src/rmodels.c:2335`). |
| `raylib` | `UpdateAudioStreamInLockedState` | Heap Buffer Overflow | **Critical** | 76.8 KB heap overflow during audio sample resynchronization (`src/raudio.c:2784`). |
| `raylib` | `LoadGLTF()` | Out-of-Bounds Read | **High** | Unchecked accessor buffer view offset causes out-of-bounds heap read (`src/rmodels.c:4897`). |
| `raylib` | `ReadAudioBufferFramesInternal` | NULL Pointer Deref | **High** | Missing device buffer check causes immediate crash in mixer callback (`src/raudio.c:2465`). |
| `raylib` | `GetCodepointPrevious()` | Heap Buffer Underflow | **Medium** | Negative buffer pointer progression on truncated UTF-8 sequences (`src/rtext.c:2592`). |
| `raylib` | `ImageBlurGaussian()` | Integer Underflow | **Medium** | Kernel radius underflow causes out-of-bounds image sample reads (`src/rtextures.c:2204`). |
| `drogon` | `HttpRequestParser.cc` | Request Smuggling | **High** | Premature header termination on malformed lines allows request desync (CWE-444). |
| `drogon` | `HttpResponseParser.cc` | Enum Out-of-Range UB | **Medium** | Unchecked HTTP status codes trigger undefined behavior in status enum mappings (CWE-843). |
| `drogon` | `MultiPart.cc` | Boundary Discrepancy | **Medium** | Semantic discrepancy between buffered and streaming multipart boundary terminators. |
| `drogon` | `HttpUtils.cc` (`isValidHeader`) | Null Byte Injection | **Medium** | Embedded null bytes in custom response headers bypass validation sanitizers (CWE-113). |

---

## Repository Layout

```text
cs5187-term-project-shadye-6/
├── paper/                             # ACM FSE Research Report (12-Page Limit)
│   ├── main.tex                       # Master LaTeX document (acmart acmsmall format)
│   ├── macros.tex                     # Mathematical notation, tool macros, system terms
│   ├── sections/                      # Modular paper sections (intro, approach, eval, ...)
│   ├── figures/                       # High-resolution TikZ architecture figures
│   ├── tables/                        # Formatted evaluation & findings LaTeX tables
│   ├── references.bib                 # Verified bibliography (upstream CVEs, PRs, literature)
│   ├── Makefile                       # One-command paper build (pdflatex + bibtex)
│   └── scripts/check.sh               # Strict 12-page ceiling and lint verification script
│
├── src/                               # Complete QTFuzz Cross-Domain Implementation
│   ├── README.md                      # Unified technical architecture & reproduction guide
│   │
│   ├── fastgltf/                      # Phase 1: 3D Parser Base Fuzzing Engine
│   │   ├── fuzz/                      # Custom mutators, UCB scheduler, AST generator
│   │   ├── harnesses/                 # libFuzzer targets (fuzz_hybrid, fuzz_parser)
│   │   ├── scripts/                   # Build, fuzzing, and coverage scripts
│   │   └── findings/                  # Defect reproducers (including F1 poc_f011)
│   │
│   ├── raylib/                        # Phase 2: Headless Multimedia Engine Fuzzer
│   │   ├── common/                    # Software rasterizer shims (rlsw), capped allocators, UCB
│   │   ├── harnesses/                 # 37 isolated target binaries (image, audio, font, model)
│   │   ├── tools/                     # Parallel runners, saturation monitors, seed generators
│   │   └── raylib_all_issues_bundle/  # Verified reproducers for R1, R2, R3 + unfiled defects
│   │
│   └── drogon/                        # Phase 3: Zero-Socket In-Memory Web Server Fuzzer
│       ├── common/                    # MockTcpConnection, MockEventLoop, IterationSandbox
│       ├── harnesses/                 # 19 network harnesses (HTTP, WebSocket, Multipart)
│       ├── dict/                      # HTTP/1.1, WebSocket, and URI grammar dictionaries
│       ├── tools/                     # Parallel multi-worker campaign drivers & triage tools
│       └── drogon-issues-and-reproducers/ # Verified reproducers for D1, D2 + patches
│
└── .gitignore                         # Build artifact and compiler intermediate ignore rules
```

---

## Quickstart: Build & Reproduce

All builds require Linux x86_64 (Ubuntu 22.04 / 24.04 LTS or WSL2) with Clang 18:

```bash
# Install system dependencies
sudo apt-get update
sudo apt-get install -y build-essential clang-18 llvm-18-dev cmake ninja-build \
                        libjsoncpp-dev libssl-dev zlib1g-dev uuid-dev libasound2-dev libx11-dev
```

### 1. Reproduce Upstream Vulnerabilities

#### Defect D1: Drogon Server DoS via `noexcept` Exception ([PR #2662](https://github.com/drogonframework/drogon/pull/2662))
```bash
cd src/drogon/drogon-issues-and-reproducers/issue-02-filesystem-noexcept-dos
clang++ -fsanitize=address,undefined -std=c++17 reproduce_standalone.cc -o repro_d1
./repro_d1
# Expected output: std::terminate called after throwing an instance of 'std::filesystem::filesystem_error'
```

#### Defect R1: Raylib Matrix Stack Underflow ([PR #6362](https://github.com/raysan5/raylib/pull/6362))
```bash
cd src/raylib
./build.sh repro
./out/repro/fuzz_render_vm raylib_all_issues_bundle/pending_issues_bundle/Issue-01_swPopMatrix_Underflow/crash.bin
# Expected output: SEGV / AddressSanitizer crash in swPopMatrix()
```

#### Defect R2: Raylib OOB Read in Automation Replay ([Issue #6378](https://github.com/raysan5/raylib/issues/6378))
```bash
cd src/raylib
./build.sh repro
./out/repro/fuzz_automation raylib_all_issues_bundle/pending_issues_bundle/Issue-01_Automation_Export_OOB_Read/crash_event_type_24.bin
# Expected output: AddressSanitizer: global-buffer-overflow in ExportAutomationEventList()
```

#### Defect F1: fastgltf Accessor Index OOB Read ([Issue #160](https://github.com/spnda/fastgltf/issues/160))
```bash
cd src/fastgltf
clang++ -std=c++17 -fsanitize=address,undefined -g -O0 \
  -Iexternal/fastgltf/include poc_f011.cpp \
  -Lbuild-asan/external/fastgltf -lfastgltf -o poc_f011
./poc_f011 findings/crashes/crash-db0170fae561bcc1186860580e462803e93ecac1
# Expected output: AddressSanitizer: heap-buffer-overflow in Parser::generateMeshIndices
```

---

## Compiling & Verifying the Research Paper

The research paper is written in ACM `acmsmall` format and enforced to a **strict 12-page limit** (main text + references).

```bash
cd paper

# 1. Compile the PDF
make

# 2. Run automated validation checks (verifies 0 LaTeX errors, page count <= 12, style rules)
bash scripts/check.sh
```

**Verification Output:**
```text
=== Checking LaTeX errors ===
Errors: 0

=== Checking TODOs ===
Found 0 TODOs.

=== Checking numerical placeholders (\num) ===
Found 0 placeholders.

=== Checking paper length ===
Paper pages: 12 (within 12-page ceiling)
References start on page: 12

ALL CHECKS PASSED.
```

---

## Detailed Documentation Links

- 📖 **[src/README.md](src/README.md):** In-depth technical dossier, mathematical UCB formulations, harness implementation details, and cross-domain reproduction manual.
- 📖 **[src/fastgltf/README.md](src/fastgltf/README.md):** 3D AST mutation engine, guarded buffer allocator, and glTF campaign execution.
- 📖 **[src/raylib/README.md](src/raylib/README.md):** Headless software rasterizer architecture, 37 multimedia targets, and linker wrapping.
- 📖 **[src/drogon/drogon-issues-and-reproducers/README.md](src/drogon/drogon-issues-and-reproducers/README.md):** In-memory zero-socket network mocks, raw crash triggers, and patches.
- 📖 **[paper/README.md](paper/README.md):** LaTeX paper compilation guide and style check instructions.

---

## License & Attribution

This term project is authored by **Dakshin**, **Neel**, and **Samyak** for the **CS-5187 Advanced Software Engineering** course at the **Indian Institute of Technology Guwahati**.  
Third-party subject libraries (`fastgltf`, `raylib`, `drogon`) are licensed under their respective MIT / Apache-2.0 upstream licenses.
