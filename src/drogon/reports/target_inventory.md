# Target Inventory & Architectural Mapping

## 1. LibFuzzer Fuzz Targets (16 Targets)

All 16 targets implement `extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)` and link libFuzzer.

### Layer 1: Pure Functions & Utility Layer
- **`fuzz_url`**: Fuzzes `drogon::utils::urlDecode` and URL components without state dependencies.
- **`fuzz_cookie`**: Fuzzes `drogon::Cookie` parsing, formatting, and `HttpRequest::addHeader("cookie", ...)`.
- **`fuzz_range`**: Fuzzes RFC 7233 byte-range parsing (`HttpRequestImpl::parseRangeHeader`).
- **`fuzz_utilities`**: Fuzzes Base64 encode/decode, gzip/brotli decompressors, and MD5, SHA1, SHA256, SHA3 utilities.

### Layer 2: Core Network Parsers
- **`fuzz_http_request_raw`**: Direct HTTP/1.x request parser fuzzing using non-blocking Trantor socketpair fixtures with linked custom mutator (OBJECT library linkage).
- **`fuzz_http_request_fragmented`**: Fuzzes request framing across 5 deterministic byte-splitting schedules (All-at-once, Byte-at-a-time, CRLF delimiters, Relative chunk offsets, 16-bit normalized offsets) with dual-format `0xF7` seed preservation and direct length decoding.
- **`fuzz_http_response_raw`**: Fuzzes response status line, chunked decoding, and Content-Length accounting with linked custom mutator.
- **`fuzz_http_response_fragmented`**: Fragmented response stream delivery across 5 deterministic delivery schedules with dual-format `0xF7` seed preservation and direct length decoding.
- **`fuzz_multipart`**: Buffered RFC 7578 multipart form parser with dual-format `0xFD` boundary handling and valid WebKit boundary matching in corpus.
- **`fuzz_multipart_stream`**: Chunked streaming multipart parser (`drogon::MultipartStreamParser`) with differential equivalence comparison against buffered parser (part counts, parameter keys/values, file binary data).
- **`fuzz_websocket_frame`**: WebSocket frame parser (RFC 6455 framing, masking keys, opcode handling).
- **`fuzz_websocket_session`**: Multi-frame WebSocket fragmentation and session state machine (Ping/Pong/Close control frames, continuous frame loop, `gotAll(msg, type)` API).

### Layer 3: High-Level Stack Integration
- **`fuzz_kitchen_sink`**: Full Drogon integration fuzzer driving routing (`/echo`, `/json`, `/form`, `/routes/{id}`), filter middleware, parameter parsing, and response generation with properly indexed Drogon event loops.

### Layer 5: Semantic & Filesystem Oracles
- **`fuzz_filesystem`**: Strictly sandboxed filesystem oracle (`CwdGuard` RAII, per-iteration disposable sandbox, confined `saveAs()`) testing `HttpFileImpl::save()`, `save(path)`, and `saveAs()`. Run inside `scripts/run_filesystem_sandbox.sh`.
- **`fuzz_response_builder`**: Fuzzes response header generation, cookie serialization, hostile CRLF rejection, and verifies absence of HTTP response splitting.

### Layer 6: Differential Testing
- **`fuzz_llhttp_differential`**: Compares Drogon's HTTP request parser against Node.js `llhttp` for ambiguous framing (duplicate headers, space before colon, TE/CL desynchronization, method and body length equivalence) with synchronized message-boundary pause (`HPE_PAUSED`).

---

## 2. Standalone Verification & Regression Test Suites (12 Suites)

All 12 regression suites implement standard `main()` and are executed automatically by `scripts/replay_regressions.sh`:

1. **`smoke_sanitizer_test`**: Validates Trantor loop lifecycle, socketpair non-blocking I/O, and event polling baseline.
2. **`smoke_sanitizer_test --verify-sanitizers`**: Executes child subprocesses triggering deliberate ASan heap-buffer-overflow and UBSan signed-integer-overflow traps to prove sanitizers are active and aborting cleanly with explicit error messages.
3. **`test_delivery_plan`**: Unit tests verifying all 5 fragmentation delivery schedules, boundary edge cases, CRLF snap points, and zero byte loss.
4. **`test_custom_mutator`**: Unit tests verifying length bounds, dictionary mutation safety, invocation counter, and `LLVMFuzzerMutate` fallback.
5. **`test_wrapper_decoders`**: Unit tests asserting byte-for-byte payload recovery across all 4 wrapper binary formats (`0xF7` request/response, `0xFD` multipart, `0xF9` websocket).
6. **`test_multipart_valid_seed`**: Validates RFC 7578 multipart form seed parsing and boundary matching with parameters and uploaded file verification.
7. **`regression_request_framing`**: Tests duplicate Content-Length, empty Content-Length, whitespace before header colons, Content-Length combined with Transfer-Encoding (RFC 9112 Section 6.3), and request pipelining after malformed requests.
8. **`regression_response_pr2650`**: Tests PR #2650 boundary conditions (`SIZE_MAX-3`, `SIZE_MAX-2`, `SIZE_MAX-1`, `SIZE_MAX`), numeric prefixes (`10abc`), signs, leading whitespace, and extreme 64-bit integer values.
9. **`regression_multipart_pr2651`**: Tests PR #2651 boundary distance underflows (`pos2 - pos1 < 4`), boundary at EOF, and `HttpRequestImpl::parseParameters` bounds safety.
10. **`test_httpfile_save_ub`**: Reproduces 3-iterator `std::equal` out-of-bounds iteration in `HttpFileImpl::save()` with trigger `../../c` under `_GLIBCXX_DEBUG` in an isolated child process, asserting that `SIGABRT` is triggered.
11. **`llhttp_differential`**: Differential analysis fixture comparing Drogon and Node.js `llhttp` on malformed framing sequences.
12. **`test_server_pipelining`**: Connects over loopback to a production `drogon::HttpServer`, verifies connection closure and disposal of pipelined data following malformed requests.
