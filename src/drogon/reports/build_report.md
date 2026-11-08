# Build and Verification Report: drogon-fuzz

## 1. Environment & Pinned Revisions
- **Target Repository:** https://github.com/drogonframework/drogon
- **Drogon Git Commit:** `df418bfdd99d4cc1ebd8598b8ced4f74d4f488ce`
- **Trantor Git Commit:** `ae1bdf6042debbaa6a7f1a13ac6165c64a0c072c`
- **Compiler Version:** Clang 18.1.3 (`x86_64-pc-linux-gnu`)
- **CMake Version:** 3.28.3
- **Operating System:** Ubuntu 24.04 LTS (under WSL2)
- **Primary Build Configurations:**
  - `build/asan`: AddressSanitizer + UndefinedBehaviorSanitizer (`-fsanitize=address,undefined -fno-omit-frame-pointer -g -O1 -D_GLIBCXX_ASSERTIONS`)
  - `build/glibcxx_debug`: Standard library debug checks (`-D_GLIBCXX_DEBUG -D_GLIBCXX_DEBUG_PEDANTIC -g -O0`)
  - `build/integer`: Integer sanitization (`-fsanitize=address,undefined,unsigned-integer-overflow,implicit-integer-conversion`)
  - `build/tsan`: ThreadSanitizer (`-fsanitize=thread`)
  - `build/release`: Maximum throughput release build (`-O3 -DNDEBUG -fsanitize=fuzzer`)

---

## 2. Target Classification & Compilation Status

The framework distinguishes between **16 libFuzzer targets** (implementing `LLVMFuzzerTestOneInput`) and **13 standalone regression, unit test, & verification executables** (implementing standard `main()`). All targets compile cleanly with zero warnings or errors.

### 2.1 LibFuzzer Fuzz Targets (16 Targets)
| Target Name | Layer | Source Path | Linkage / Engine | Smoke Test Status |
| :--- | :--- | :--- | :--- | :--- |
| `fuzz_url` | L1 Pure | `harness/l1_pure/url/fuzz_url.cc` | LibFuzzer + Drogon | **PASSED** (cov: 199, 49 seeds) |
| `fuzz_cookie` | L1 Pure | `harness/l1_pure/cookie/fuzz_cookie.cc` | LibFuzzer + Drogon | **PASSED** (cov: 377, 6 seeds) |
| `fuzz_range` | L1 Pure | `harness/l1_pure/range/fuzz_range.cc` | LibFuzzer + Drogon | **PASSED** (cov: 61, 16 seeds) |
| `fuzz_utilities` | L1 Pure | `harness/l1_pure/utilities/fuzz_utilities.cc` | LibFuzzer + Drogon | **PASSED** (cov: 248, 43 seeds) |
| `fuzz_http_request_raw` | L2 Parser | `harness/l2_parser/http_request/fuzz_http_request_raw.cc` | LibFuzzer + Mutator OBJECT + Drogon | **PASSED** (cov: 1062, 44 seeds) |
| `fuzz_http_request_fragmented` | L2 Parser | `harness/l2_parser/http_request/fuzz_http_request_fragmented.cc` | LibFuzzer + Drogon | **PASSED** (cov: 1034, 39 seeds) |
| `fuzz_http_response_raw` | L2 Parser | `harness/l2_parser/http_response/fuzz_http_response_raw.cc` | LibFuzzer + Mutator OBJECT + Drogon | **PASSED** (cov: 955, 45 seeds) |
| `fuzz_http_response_fragmented` | L2 Parser | `harness/l2_parser/http_response/fuzz_http_response_fragmented.cc` | LibFuzzer + Drogon | **PASSED** (cov: 1054, 45 seeds) |
| `fuzz_multipart` | L2 Parser | `harness/l2_parser/multipart/fuzz_multipart.cc` | LibFuzzer + Drogon | **PASSED** (cov: 469, 27 seeds) |
| `fuzz_multipart_stream` | L2 Parser | `harness/l2_parser/multipart_stream/fuzz_multipart_stream.cc` | LibFuzzer + Drogon | **PASSED** (cov: 838, 38 seeds) |
| `fuzz_websocket_frame` | L2 Parser | `harness/l2_parser/websocket/fuzz_websocket_frame.cc` | LibFuzzer + Drogon | **PASSED** (cov: 161, 36 seeds) |
| `fuzz_websocket_session` | L2 Parser | `harness/l2_parser/websocket/fuzz_websocket_session.cc` | LibFuzzer + Drogon | **PASSED** (cov: 235, 32 seeds) |
| `fuzz_filesystem` | L5 Semantic | `harness/l5_semantic/filesystem/fuzz_filesystem.cc` | LibFuzzer + Drogon | **PASSED** via `run_filesystem_sandbox.sh` (cov: 522, 14 corp) |
| `fuzz_response_builder` | L5 Semantic | `harness/l5_semantic/response/fuzz_response_builder.cc` | LibFuzzer + Drogon | **PASSED** (cov: 1239, 20 seeds) |
| `fuzz_kitchen_sink` | L3 Stack | `harness/l3_stack/kitchen_sink/fuzz_kitchen_sink.cc` | LibFuzzer + Drogon | **PASSED** (cov: 2086, 28 seeds) |
| `fuzz_llhttp_differential` | L6 Diff | `harness/l6_differential/llhttp/fuzz_llhttp_differential.cc` | LibFuzzer + llhttp + Drogon | **PASSED** (cov: 1229, 33 seeds) |

### 2.2 Standalone Verification & Regression Test Suites (12 Suites)
| Suite Name | Source Path | Preset / Engine | Verification Result |
| :--- | :--- | :--- | :--- |
| `smoke_sanitizer_test` (Baseline) | `harness/common/smoke_sanitizer_test.cc` | Standalone + Trantor | **PASSED** |
| `smoke_sanitizer_test --verify-sanitizers` | `harness/common/smoke_sanitizer_test.cc` | Subprocess ASan/UBSan | **PASSED** (Explicit ASan/UBSan diagnostics verified) |
| `test_delivery_plan` | `harness/common/test_delivery_plan.cc` | Unit Test | **PASSED** (5 modes & CRLF splitting verified) |
| `test_custom_mutator` | `mutators/test_custom_mutator.cc` | Unit Test | **PASSED** (Length bounds & invocation verified) |
| `test_wrapper_decoders` | `harness/common/test_wrapper_decoders.cc` | Unit Test | **PASSED** (4 decoder formats byte-for-byte verified) |
| `test_multipart_valid_seed` | `harness/l2_parser/multipart/test_multipart_valid_seed.cc` | Unit Test | **PASSED** (WebKit boundary seed verified) |
| `regression_request_framing` | `harness/l2_parser/http_request/regression_request_framing.cc` | Standalone + Drogon | **PASSED** (RFC 9112 Sec 6.3 verified) |
| `regression_response_pr2650` | `harness/l2_parser/http_response/regression_response_pr2650.cc` | Standalone + Drogon | **PASSED** (PR #2650 bounds verified) |
| `regression_multipart_pr2651` | `harness/l2_parser/multipart/regression_multipart_pr2651.cc` | Standalone + Drogon | **PASSED** (PR #2651 bounds verified) |
| `test_httpfile_save_ub` | `harness/l5_semantic/filesystem/test_httpfile_save_ub.cc` | `_GLIBCXX_DEBUG` | **PASSED** (SIGABRT & `_M_cur != _M_cmpts.end()` caught) |
| `llhttp_differential` | `harness/l6_differential/llhttp/llhttp_differential.cc` | Standalone + llhttp | **PASSED** (Edge cases verified) |
| `test_server_pipelining` | `harness/l7_network/pipelining/test_server_pipelining.cc` | Standalone + HttpServer | **PASSED** (Discard verified) |

### 2.3 Verification Tooling
- `verify_parser_states`: Standalone verification utility (`harness/common/verify_parser_states.cc`) asserting terminal parser states (`kGotAll`), method, path, and body assertions across seed inputs before coverage collection.

---

## 3. Test Suites & Verification Execution

1. **Smoke Tests (`scripts/run_smoke_tests.sh`):**
   - 15 non-filesystem libFuzzer targets executed 50 iterations against their respective seed corpora under ASan/UBSan.
   - Result: 15/15 Passed cleanly (exit code 0), coverage metrics logged in `reports/smoke_tests.log`.
2. **Filesystem Mount Sandbox (`scripts/run_filesystem_sandbox.sh`):**
   - `fuzz_filesystem` executed inside an isolated container mount namespace (`unshare --user --mount --map-root-user`) with a private `tmpfs` mounted at `/tmp`.
   - Result: Passed cleanly, verified strict directory containment.
3. **Regression Replay (`scripts/replay_regressions.sh`):**
   - 12/12 test suites executed and passed cleanly.
4. **Deterministic Seed Coverage (`scripts/verify_coverage.sh`):**
   - Semantic parser state verification via `verify_parser_states` followed by bounded `-runs=1` replay across key parser state machines.
   - Exact coverage counters emitted and recorded in `reports/coverage_verification.log`.
5. **Crash Triage Tooling (`scripts/triage_crashes.py`):**
   - Validated against test crash inputs, extracting stack traces, signals, and generating deduplicated reports.
