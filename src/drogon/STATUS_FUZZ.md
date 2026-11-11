# Drogon-Fuzz Implementation & Verification Status

## Phase 0: Build Foundation & Audit
- [x] Pinned source revisions recorded in `docs/source-revisions.md` (Drogon `df418bfdd99d4cc1ebd8598b8ced4f74d4f488ce`, Trantor `ae1bdf6042debbaa6a7f1a13ac6165c64a0c072c`).
- [x] Initial source audit completed and documented in `docs/source-audit.md`.
- [x] Target inventory mapped in `docs/target-map.md` and `reports/target_inventory.md`.
- [x] Parser state machines documented in `docs/http-request-parser.md` and `docs/http-response-parser.md`.
- [x] CMake build infrastructure configured with multiple fallback paths (`../drogon`, `drogon`, `../../drogon`, or `-DDROGON_SRC_DIR`).
- [x] ASan + UBSan preset validated with compiler smoke test (`smoke_sanitizer_test`).
- [x] Subprocess ASan & UBSan explicit trap diagnostic verification (`smoke_sanitizer_test --verify-sanitizers`, asserting `AddressSanitizer: heap-buffer-overflow` and `runtime error: signed integer overflow`).
- [x] Standard library debug preset configured and validated (`cmake/sanitizer-presets/glibcxx_debug.cmake`).
- [x] Integer sanitizer preset configured and validated (`cmake/sanitizer-presets/integer.cmake`).
- [x] High-throughput release preset configured and validated (`cmake/sanitizer-presets/release.cmake` with `-fsanitize=fuzzer`).
- [x] Trantor `TcpConnectionImpl` lifecycle fixture verified (`connectEstablished`, draining, forceClose/handleClose, `connectDestroyed`, event loop indexing).
- [x] Curated wrapper format decoders unit-tested (`test_wrapper_decoders`, verifying byte-for-byte payload recovery across all 4 wrapper formats).

## Phase 1: Pure-Function Targets (L1)
- [x] `fuzz_url`: built, smoke-tested (cov: 199, 49 seeds).
- [x] `fuzz_cookie`: built, expanded to fuzz `HttpRequest::addHeader("cookie", ...)`, smoke-tested (cov: 377, 6 seeds).
- [x] `fuzz_range`: built, smoke-tested (cov: 61, 16 seeds).
- [x] `fuzz_utilities`: built, expanded to fuzz Base64 encode/decode, MD5/SHA hashes, gzip, brotli, smoke-tested (cov: 248, 43 seeds).
- [x] Seed corpus generated and verified for all L1 targets (>0 seeds each).

## Phase 2: HTTP Request Parser (L2)
- [x] `fuzz_http_request_raw`: built, custom mutator linked directly via CMake OBJECT library (`$<TARGET_OBJECTS:drogon_custom_mutator>`), verified non-weak global symbol in `.text`, smoke-tested (cov: 1062, 44 seeds).
- [x] `fuzz_http_request_fragmented`: direct `scheduleLen` decoding without off-by-one, 5 delivery modes (All-at-once, Byte-at-a-time, CRLF snap points, Relative chunk offsets, 16-bit normalized offsets), smoke-tested (cov: 1034, 39 seeds).
- [x] `regression_request_framing` executed and verified:
  - Duplicate Content-Length (identical & conflicting).
  - Empty Content-Length.
  - Whitespace before colon (`Content-Length : 5`).
  - Content-Length + Transfer-Encoding combination (RFC 9112 Section 6.3 rejected with 400).
  - Pipelined requests following malformed frames (Drogon stops parser and terminates buffer).
- [x] Two-recipient differential framing analysis with `llhttp` (`llhttp_differential`).
- [x] Production `drogon::HttpServer` pipelining integration test (`test_server_pipelining`): verifies socket draining and connection closure upon malformed requests.

## Phase 3: HTTP Response Parser (L2)
- [x] `fuzz_http_response_raw`: built, custom mutator linked directly via OBJECT library, smoke-tested (cov: 955, 45 seeds).
- [x] `fuzz_http_response_fragmented`: direct `scheduleLen` decoding, 5 delivery modes, smoke-tested (cov: 1054, 45 seeds).
- [x] `regression_response_pr2650` executed and verified:
  - Boundary values: `SIZE_MAX-3` (accepted), `SIZE_MAX-2` (accepted), `SIZE_MAX-1` (rejected), `SIZE_MAX` (rejected).
  - Numeric prefix Content-Length values (`10abc`, `+10`, leading spaces).
  - Extreme overflow `18446744073709551616` (2^64) safely rejected.
  - Body-consumption accounting verified.

## Phase 4: Multipart (L2)
- [x] `fuzz_multipart`: direct `boundaryLen` decoding, standard WebKit boundary match in seed corpus (`----WebKitFormBoundary7MA4YWxkTrZu0gW`), smoke-tested (cov: 469, 27 seeds).
- [x] `fuzz_multipart_stream`: streaming part accumulator (`StreamedPart`), normalized equivalence comparison against buffered parser (part count, parameter keys/values, and exact file binary content), smoke-tested (cov: 838, 38 seeds).
- [x] Multipart valid seed test suite executed (`test_multipart_valid_seed`, asserting parameters and file content).
- [x] `regression_multipart_pr2651` executed and verified:
  - Boundary distance underflow (`pos2 - pos1 < 4`).
  - Boundary at EOF (`content.size() - pos1 < 2`).
  - `HttpRequestImpl::parseParameters` bounds check regression.

## Phase 5: WebSocket & Filesystem (L2/L5)
- [x] `fuzz_websocket_frame`: RFC 6455 framing, masking keys, opcode handling, smoke-tested (cov: 161, 36 seeds).
- [x] `fuzz_websocket_session`: multi-frame continuous parser loop with correct `gotAll(msg, type)` API, Ping/Pong/Close control frames, fragmentation, smoke-tested (cov: 235, 32 seeds).
- [x] `fuzz_filesystem`: CWD restoration RAII guard (`CwdGuard`), disposable per-iteration sandbox (`IterationSandbox` using `mkdtemp`), confined `saveAs()` destination, separate test validation phases, strict `isSubpath()` containment check using canonicalized absolute paths, smoke-tested via `scripts/run_filesystem_sandbox.sh` (cov: 522, 14 corp).
- [x] Dedicated OS-level filesystem isolation script (`scripts/run_filesystem_sandbox.sh`) providing `unshare --user --mount --map-root-user` with read-only root and private `tmpfs` at `/tmp`.
- [x] `test_httpfile_save_regression`: verifies safe rejection (-1) on traversal and persistence (0) on legitimate nested uploads against fixed Drogon.
- [x] `test_httpfile_save_ub`: isolated subprocess execution with trigger `../../c`, asserts explicit `_M_cur != _M_path->_M_cmpts.end()` assertion from libstdc++ against unpatched baseline.
- [x] `fuzz_filesystem`: snapshot-based containment diff oracle (`takeSnapshot`, `diffSnapshots`), input-derived `saveAs` destination, strict `isSubpath()` containment verification, and bubblewrap OS-level isolation (`scripts/run_filesystem_sandbox.sh`).
- [x] `noexcept` filesystem operations audited and documented as candidate source-audit finding (`findings/finding-02-noexcept-filesystem-exceptions/finding.md`).
- [x] `fuzz_response_builder`: RFC 7230 token header validation, whitespace trimming alignment, cookie preservation, hostile CRLF header injection rejection, and response-splitting detection, smoke-tested (cov: 1239, 20 seeds).

## Phase 6: Differential & Higher-Level Targets
- [x] `fuzz_llhttp_differential`: genuine libFuzzer target implementing `LLVMFuzzerTestOneInput`, synchronized message-boundary pause via `HPE_PAUSED`, exact consumed-byte boundary alignment, and acceptance/rejection mismatch recording to `/tmp/drogon_differential_mismatches/`, smoke-tested (cov: 1229, 33 seeds).
- [x] `llhttp_differential`: standalone static regression test comparing edge cases.
- [x] `fake_http_server`: real loopback HTTP server fixture testing `drogon::HttpClient` against malformed upstream responses.
- [x] `fuzz_kitchen_sink`: integration fuzzer driving routing, JSON, forms, path parameters, resolved `IOThreadStorage` event loop index initialization, smoke-tested (cov: 2086, 28 seeds).
- [x] `test_server_pipelining`: verified on production `drogon::HttpServer` listening on ephemeral loopback port.

## Phase 7: Tooling & Readiness
- [x] Target-specific dictionaries created (`http.dict`, `multipart.dict`, `websocket.dict`, `uri.dict`).
- [x] Custom mutator ABI `LLVMFuzzerCustomMutator` implemented with length-safe search, mt19937 PRNG, atomic counter `g_customMutatorInvocations`, and `LLVMFuzzerMutate` fallback (`mutators/custom_mutator.cc`, verified by `test_custom_mutator`).
- [x] Triage tool `triage_crashes.py` created and verified.
- [x] Regression replay script `replay_regressions.sh` verified (13/13 test suites PASSING including fake_http_server and test_httpfile_save_regression).
- [x] Smoke test script `run_smoke_tests.sh` verified (15/15 non-filesystem fuzz targets PASSING with active coverage metrics).
- [x] Filesystem sandbox script `run_filesystem_sandbox.sh` verified (mount namespace container execution PASSING).
- [x] Deterministic seed replay script `verify_coverage.sh` verified (bounded `-runs=1` execution, `verify_parser_states` terminal confirmation, exact coverage metrics logged).
- [x] Reports updated (`reports/build_report.md`, `reports/target_inventory.md`, `reports/smoke_tests.log`, `reports/coverage_verification.log`).
- [x] All shell scripts given executable permissions (`0755`).
- [x] Comprehensive `README.md` created with prerequisites, build steps, and reproduction instructions.
- [x] Hard restriction maintained: User notified before starting live continuous fuzzing campaigns.
