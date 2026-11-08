# Preliminary Security & Robustness Findings

During harness construction, static analysis, and seed verification, the following defects and discrepancies were identified and independently reproduced:

## 1. Out-of-Bounds Iterator Dereference in HttpFileImpl::save()
- **Location:** `drogon/lib/src/HttpFileImpl.cc` (line 71)
- **Defect Classification:** Standard library algorithm precondition violation / Out-of-bounds dereference.
- **Trigger Condition:** Any multipart file upload filename that causes `std::filesystem::weakly_canonical(uploadDir / fileName)` to have fewer path components than `uploadDir` while matching its prefix components (e.g., `fileName = ".."` or `../../..//../..`).
- **Reproduction:** Confirmed via `test_httpfile_save_ub` and LibFuzzer target `fuzz_filesystem` (terminates with `SIGABRT` due to libstdc++ assertion failure `_M_cur != _M_path->_M_cmpts.end()`).
- **Impact:** Server crash / Denial of Service triggered by untrusted user upload inputs.
- **Artifact:** `findings/finding-01-httpfile-path-iterator-oob/crash_repro.bin`

## 2. Unhandled std::filesystem Exceptions in noexcept File-Save Methods
- **Location:** `drogon/lib/src/HttpFileImpl.cc` (lines 48, 51, 53, 67, 99)
- **Defect Classification:** `noexcept` specification violation leading to `std::terminate()`.
- **Trigger Condition:** Filesystem errors during `current_path()`, `weakly_canonical()`, or `exists()` within `save()` or `saveAs()`.
- **Impact:** Server abort on unexpected filesystem states or permissions.
- **Detailed Report:** `findings/finding-02-noexcept-filesystem-exceptions/finding.md`

## 3. Discrepancies Identified in Two-Recipient Differential Testing
- **Location:** `drogon/lib/src/HttpRequestParser.cc` vs. `llhttp`
- **Observations:**
  - *Whitespace before colon (`Content-Length : 5`):* Drogon treats `Content-Length ` as an unrecognized header and accepts the request without reading 5 body bytes; `llhttp` rejects with HTTP 400.
  - *Duplicate Content-Length (`5` vs `10`):* Drogon stores headers in a map where the first entry takes precedence and accepts the request; `llhttp` strictly rejects conflicting duplicates with HTTP 400.
  - *Mitigating Factor:* When any malformed request framing error occurs, Drogon's `HttpServer` closes the connection and discards remaining buffered bytes, preventing downstream pipelined request reuse.

