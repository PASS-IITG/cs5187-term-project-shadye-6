# DNSFuzz: Cross-Domain Adaptive Fuzzer Codebase (`src/`)

This directory contains the complete source code, mutation operators, multi-armed bandit schedulers, headless in-memory shims, subsystem fuzz harnesses, campaign orchestration scripts, seed corpora, and vulnerability reproducers for **DNSFuzz**.

---

## 1. Architectural Overview & Evolutionary Flow

DNSFuzz was engineered to address a fundamental challenge in coverage-guided fuzzing: testing heterogeneous, multi-layered C and C++ software stacks without sacrificing execution speed or domain-specific structural intelligence. The project follows a three-phase evolutionary roadmap:

```
[Phase 1: Base Engine]         [Phase 2: Multimedia Extension]      [Phase 3: Network Extension]
      fastgltf                              raylib                              drogon
  (3D Asset Parser)               (Game & Rendering Engine)            (Asynchronous Web Server)
 ───────────────────────         ───────────────────────────          ───────────────────────────
 • Structure-aware mutators      • 37 decoupled target harnesses      • In-memory MockTcpConnection
 • UCB1 bandit scheduler         • Headless software rasterizer       • Tail-scheduled chunk slicing
 • Binary chunk parsing          • Linker coverage interception       • Temporary upload sandboxing
 • 3 target harnesses            • 37 target harnesses                • 19 target harnesses
 • 3.2M campaign inputs          • 54.3M campaign inputs              • 750M campaign inputs
```

1. **Phase 1: Base Engine (`src/fastgltf/`)**
   We began by building a structure-aware hybrid fuzzing engine for the `fastgltf` 3D model parsing library. glTF 2.0 assets contain interleaved JSON metadata and binary geometry buffers, causing flat byte mutators to saturate early. We introduced an adaptive multi-armed bandit (Discounted-UCB1) scheduler that balances structured AST mutation, binary geometry modification, integer boundary injection, and byte-level mutations.

2. **Phase 2: Multimedia & Graphics Extension (`src/raylib/`)**
   We generalized the base mutation and scheduling architecture to interactive multimedia systems using `raylib`. Unlike file parsers, game engines expect display servers, framebuffers, and audio mixing devices. We resolved this through subsystem decomposition ("One Source, Many Binaries"), splitting the engine into 37 isolated target binaries running with headless rendering mocks over the software rasterizer (`rlsw`). To prevent compiler symbol collisions with libFuzzer in Clang 18, we introduced GNU linker symbol wrapping (`-Wl,--wrap=__sanitizer_cov_trace_pc_guard`) for independent coverage reward tracking.

3. **Phase 3: Asynchronous Networking Extension (`src/drogon/`)**
   Finally, we extended the architecture to high-concurrency web servers using `drogon`. Traditional network fuzzers communicate over operating system loopback sockets, capping execution throughput to hundreds of iterations per second. We bypassed OS network overhead by creating `MockTcpConnection`, an in-memory C++ abstraction capturing the `trantor::TcpConnection` interface and thread-local `EventLoop`. We added tail-scheduled chunk slicing to test packet fragmentation without corrupting seed payloads, achieving over 53,000 executions per second directly in user space.

---

## 2. Pinned Environment & Prerequisites

All target systems, mutation engines, and harnesses compile and execute under the following pinned environment:

| Property | Value |
| :--- | :--- |
| **Operating System** | Linux x86_64 (Ubuntu 24.04 LTS under WSL2 / Native Linux) |
| **Compiler Suite** | Clang 18.1.3 (`clang`, `clang++`, `llvm-profdata`, `llvm-cov`) |
| **C/C++ Standards** | C11 (`-std=c11`), C++17 (`-std=c++17`) |
| **Build Tools** | CMake 3.28+, Ninja 1.11+, Make |
| **Sanitizers** | AddressSanitizer (`-fsanitize=address`) & UndefinedBehaviorSanitizer (`-fsanitize=undefined`) |
| **Fuzzing Engine** | LLVM libFuzzer (`-fsanitize=fuzzer`) |
| **Linker** | GNU `ld` with symbol wrapping support (`-Wl,--wrap`) |
| **Python Support** | Python 3.10+ (standard library for monitoring, corpus minimization, and telemetry) |

To install build prerequisites on Ubuntu / Debian:
```bash
sudo apt-get update
sudo apt-get install -y build-essential clang-18 llvm-18-dev cmake ninja-build \
                        libjsoncpp-dev libssl-dev zlib1g-dev uuid-dev libasound2-dev libx11-dev
```

---

## 3. Directory Layout

```
src/
├── fastgltf/                      # Phase 1: Base structure-aware fuzzer for glTF 2.0
│   ├── CMakeLists.txt             # Build configuration for fastgltf targets
│   ├── fuzz/                      # Mutators, Discounted-UCB scheduler, telemetry
│   │   ├── custom_mutator.cpp     # Multi-family hybrid mutator implementation
│   │   ├── mutation_scheduler.cpp # Discounted-UCB bandit selection algorithm
│   │   ├── gltf_generator.cpp     # Procedural glTF grammar generator
│   │   └── mutation_telemetry.cpp # In-memory bandit ledger and reward attribution
│   ├── harnesses/                 # Target binaries (fuzz_hybrid, fuzz_parser)
│   ├── scripts/                   # Automated build, fuzz, and evaluation scripts
│   └── findings/                  # Defect reproducers, crash artifacts, and logs
│
├── raylib/                        # Phase 2: Multimedia extension (37 targets)
│   ├── build.sh                   # Unified build script (libfuzzer, afl, repro, cov)
│   ├── common/                    # Subsystem shims and headless mocks
│   │   ├── fuzz_common.h          # Parameter readers, headless stubs, capped allocators
│   │   ├── fuzz_ucb.c             # Multi-armed bandit coverage interception wrapper
│   │   └── standalone_main.c      # Zero-dependency crashing input reproducer harness
│   ├── harnesses/                 # 37 subsystem harnesses (image_ops, render_vm, audio, ...)
│   ├── tools/                     # Corpus generation, worker runners, and saturation monitors
│   └── raylib_all_issues_bundle/  # Verified defect reproducers and test cases
│
└── drogon/                        # Phase 3: Network and asynchronous I/O extension
    ├── build.sh                   # Target compilation script with in-memory shims
    ├── common/                    # In-memory socket mocks and sandboxing
    │   ├── fuzz_mock.h            # MockTcpConnection, MockEventLoop, IterationSandbox
    │   ├── fuzz_mock.cc           # Memory buffer pump and tail-scheduled slicing
    │   └── standalone_main.cc     # Standalone defect replay harness
    ├── harnesses/                 # 19 network harnesses (http_request, multipart, websocket)
    ├── dict/                      # Grammar dictionaries for HTTP, WebSocket, URI, and JSON
    ├── tools/                     # Multi-core runner, campaign monitors, and triage scripts
    └── drogon-issues-and-reproducers/ # Standalone reproducers and crash verification scripts
```

---

## 4. How to Build and Run Fuzzing Campaigns

### 4.1 Subsystem 1: `fastgltf` (3D Asset Parser)

1. **Build the Fuzzing Targets:**
   ```bash
   cd src/fastgltf
   ./scripts/build.sh
   ```
   This compiles the library with Clang 18, ASan, UBSan, and the custom UCB mutator into `build/`.

2. **Run the Adaptive Fuzzing Target:**
   ```bash
   ./scripts/fuzz.sh hybrid 1800
   ```
   Or run the binary directly with libFuzzer flags:
   ```bash
   ./build/fuzz_hybrid seeds/ -dict=dict/gltf.dict -max_len=1048576 -timeout=25
   ```

3. **Inspect Bandit Telemetry:**
   Bandit arm weights, operator yields, and saturation metrics are logged periodically to stdout and recorded in `fuzz_telemetry.csv`.

---

### 4.2 Subsystem 2: `raylib` (Multimedia Engine)

1. **Build the 37 Subsystem Targets:**
   ```bash
   cd src/raylib
   ./build.sh libfuzzer
   ```
   Binaries are compiled into `out/libfuzzer/`.

2. **Run Representative Subsystem Targets:**
   - **Software Rasterizer & Matrix Stack (`fuzz_render_vm`):**
     ```bash
     ./out/libfuzzer/fuzz_render_vm seeds/fuzz_render_vm -runs=1000000 -max_len=8192
     ```
   - **Image Transformation VM (`fuzz_image_ops`):**
     ```bash
     ./out/libfuzzer/fuzz_image_ops seeds/fuzz_image_ops -runs=1000000 -max_len=16384
     ```
   - **Audio Decoding & Stream Conversion (`fuzz_audio_wav`):**
     ```bash
     ./out/libfuzzer/fuzz_audio_wav seeds/fuzz_audio_wav -runs=1000000 -max_len=65536
     ```
   - **Automation Event Replay (`fuzz_automation`):**
     ```bash
     ./out/libfuzzer/fuzz_automation seeds/fuzz_automation -runs=1000000 -max_len=4096
     ```

3. **Run Multi-Worker Ensemble:**
   ```bash
   tools/run_libfuzzer.sh 16 24    # 16 workers, 24-hour campaign
   ```

---

### 4.3 Subsystem 3: `drogon` (Asynchronous Web Framework)

1. **Build the 19 Network Targets:**
   ```bash
   cd src/drogon
   ./build.sh libfuzzer
   ```
   Binaries are compiled into `out/libfuzzer/`.

2. **Run Representative Network Targets:**
   - **HTTP Request Framing & Pipeline Parsing:**
     ```bash
     ./out/libfuzzer/fuzz_http_request seeds/fuzz_http_request -dict=dict/http.dict -runs=1000000
     ```
   - **Multipart Form & File Upload Decoder:**
     ```bash
     ./out/libfuzzer/fuzz_multipart_form seeds/fuzz_multipart_form -dict=dict/multipart.dict -runs=1000000
     ```
   - **WebSocket Frame Parser:**
     ```bash
     ./out/libfuzzer/fuzz_websocket seeds/fuzz_websocket -dict=dict/websocket.dict -runs=1000000
     ```

3. **Run Multi-Worker Campaign with Tail Slicing:**
   ```bash
   tools/run_libfuzzer.sh 16 24    # 16 workers, 24-hour campaign
   ```

---

## 5. Verified Vulnerabilities & Standalone Reproducers

DNSFuzz uncovered **6 verified vulnerabilities** across the three subject systems. Each defect has a standalone, zero-dependency C/C++ reproducer that verifies the issue without requiring the fuzzer runtime.

### Summary Table

| ID | Subject | Component & Function | Vulnerability Classification | CWE | Upstream Status |
| :---: | :--- | :--- | :--- | :---: | :--- |
| **F1** | `fastgltf` | `Parser::generateMeshIndices` | Heap Buffer Overflow | CWE-122 | **Closed**; fixed in upstream commit |
| **R1** | `raylib` | `swPopMatrix()` in `rlsw.h` | Matrix Stack Underflow | CWE-119 | **Acknowledged**; PR #6362 open |
| **R2** | `raylib` | `ExportAutomationEventList()` | Out-of-Bounds Global Array Read | CWE-125 | **Acknowledged**; Issue #6378 |
| **R3** | `raylib` | `LoadWaveSamples()` | NULL Pointer Dereference | CWE-476 | **Acknowledged**; PR #6374 open |
| **D1** | `drogon` | `HttpFileImpl::save()` | Process Abort in `noexcept` Method | CWE-755 | **Closed**; PR #2662 merged |
| **D2** | `drogon` | `HttpFileImpl::save()` | Out-of-Bounds Iterator Dereference | CWE-125 | **Closed**; PR #2656 / PR #2659 |

---

### 5.1 Reproducing Defect F1 (`fastgltf`)
- **Bug Description:** When parsing glTF files with primitives lacking index buffers, `Parser::generateMeshIndices` reads accessor indices without bounds checking against the total accessor count, causing out-of-bounds heap memory reads.
- **Reference:** Upstream Issue [#160](https://github.com/spnda/fastgltf/issues/160).
- **Reproduction Command:**
  ```bash
  cd src/fastgltf
  clang++ -fsanitize=address,undefined -std=c++17 -Iinclude \
          findings/known/issue_160_reproducer.cpp -Lbuild -lfastgltf -o repro_f1
  ./repro_f1
  ```

---

### 5.2 Reproducing Defect R1 (`raylib`)
- **Bug Description:** In the software rasterizer (`src/external/rlsw.h`), calling `swPopMatrix()` when `stackModelviewCounter == 1` causes an unsigned integer underflow (`--counter - 1 = -1`), corrupting the active transform pointer and causing a crash on the subsequent draw call.
- **Reference:** Upstream Issue [#6361](https://github.com/raysan5/raylib/issues/6361), Pull Request [#6362](https://github.com/raysan5/raylib/pull/6362).
- **Reproduction Command:**
  ```bash
  cd src/raylib
  ./build.sh repro
  ./out/repro/fuzz_render_vm raylib_all_issues_bundle/pending_issues_bundle/Issue-01_swPopMatrix_Underflow/crash.bin
  ```

---

### 5.3 Reproducing Defect R2 (`raylib`)
- **Bug Description:** In `src/rcore.c`, `autoEventTypeName()` indexes into the fixed array `autoEventTypeNames[24]` using unvalidated `event.type`. Providing `event.type >= 24` reads unmapped memory.
- **Reference:** Upstream Issue [#6378](https://github.com/raysan5/raylib/issues/6378).
- **Reproduction Command:**
  ```bash
  cd src/raylib
  ./build.sh repro
  ./out/repro/fuzz_automation raylib_all_issues_bundle/pending_issues_bundle/Issue-01_Automation_Export_OOB_Read/crash_event_type_24.bin
  ```

---

### 5.4 Reproducing Defect R3 (`raylib`)
- **Bug Description:** In `src/raudio.c`, `LoadWaveSamples()` does not check whether `RL_MALLOC()` returns `NULL` on oversized sample allocations, immediately dereferencing address zero during format conversion.
- **Reference:** Upstream Issue [#6373](https://github.com/raysan5/raylib/issues/6373), Pull Request [#6374](https://github.com/raysan5/raylib/pull/6374).
- **Reproduction Command:**
  ```bash
  cd src/raylib
  ./build.sh repro
  ./out/repro/fuzz_audio_wav raylib_all_issues_bundle/pending_issues_bundle/Issue-06_Audio_Mixer_Buffer_NULL_Deref/crash_alloc_fail.bin
  ```

---

### 5.5 Reproducing Defect D1 (`drogon`)
- **Bug Description:** In `HttpFileImpl::save()` and `saveAs()`, methods declared `noexcept` invoke throwing overloads of `std::filesystem::exists`. When an upload filename exceeds 255 bytes, `std::filesystem_error` is thrown, triggering `std::terminate()` and killing the entire web server process.
- **Reference:** Upstream Pull Request [#2662](https://github.com/drogonframework/drogon/pull/2662) (Addresses Issue #2661).
- **Reproduction Command:**
  ```bash
  cd src/drogon/drogon-issues-and-reproducers/issue-02-filesystem-noexcept-dos
  clang++ -fsanitize=address,undefined -std=c++17 reproduce_standalone.cc -o repro_d1
  ./repro_d1
  ```

---

### 5.6 Reproducing Defect D2 (`drogon`)
- **Bug Description:** In `HttpFileImpl::save()`, path traversal validation advances iterators over target path components without verifying that the source iterator has not reached `end()`, causing out-of-bounds iterator dereferencing under directory traversal prefixes such as `../../c`.
- **Reference:** Upstream Pull Request [#2656](https://github.com/drogonframework/drogon/pull/2656) / [#2659](https://github.com/drogonframework/drogon/pull/2659).
- **Reproduction Command:**
  ```bash
  cd src/drogon/drogon-issues-and-reproducers/issue-01-httpfile-iterator-oob
  clang++ -fsanitize=address,undefined -std=c++17 reproduce_standalone.cc -o repro_d2
  ./repro_d2
  ```

---

## 6. Campaign Execution Metrics

Across 24-hour evaluation campaigns on an x86_64 AMD workstation (16 logical cores, Ubuntu 24.04 LTS), DNSFuzz executed **807,520,128 cumulative inputs** across 59 target binaries:

| Subsystem | Targets | LoC | Total Iterations | Peak Throughput | Discovered Edges | Verified Defects |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| `fastgltf` (3D Parser) | 3 | 14,280 | 3,200,000 | 145 exec/s | 4,218 | 1 (F1) |
| `raylib` (Multimedia Engine) | 37 | 118,940 | 54,320,128 | 8,920 exec/s | 47,121 | 3 (R1, R2, R3) |
| `drogon` (Asynchronous Web Server) | 19 | 68,410 | 750,000,000 | 53,732 exec/s | 3,178 | 2 (D1, D2) |
| **Total** | **59** | **201,630** | **807,520,128** | **53,732 exec/s** | — | **6** |
