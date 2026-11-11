# Drogon Security Issues, Triggers, Logs & Reproducers Compendium

This bundle contains complete documentation, raw fuzz trigger payloads, standalone C++ reproducers, AddressSanitizer/UBSan logs, and remediation patches for all vulnerabilities and architectural discrepancies identified in the **Drogon C++ Web Framework** during our security auditing and 1-hour multi-worker parallel fuzzing campaigns.

---

## 1. Vulnerability & Findings Matrix

| Issue ID | Defect Class | CWE | Severity | Affected Component | Trigger / Artifact | Status |
| :--- | :--- | :---: | :---: | :--- | :--- | :---: |
| **Issue 01** | Out-of-Bounds Iterator Dereference | CWE-125 | **High** | `HttpFileImpl::save()` | `reproducer_prefix_traversal.bin` (`../../c`) | Closed; issue raised, fixed by maintainer in PR [#2656](https://github.com/drogonframework/drogon/pull/2656) |
| **Issue 02** | Uncaught Exception in `noexcept` (Application DoS) | CWE-755 / CWE-248 | **High** | `HttpFileImpl::save()` & `saveAs()` | `crash-65e67953a3b9503f...` (filename > 255 B) | Closed; PR [#2662](https://github.com/drogonframework/drogon/pull/2662) merged upstream (Fixes [#2661](https://github.com/drogonframework/drogon/issues/2661)) |
| **Issue 03** | Undefined Behavior / Out-of-Range Enum | CWE-843 | **Medium** | `HttpResponseParser.cc` & `HttpTypes.h` | `crash-6cb7836dc05ed7...` (status code 20020/707) | Patch provided (`0003-...patch`) |
| **Issue 04** | Multipart Boundary Semantic Desync | RFC 2046 | **Medium** | `MultiPart.cc` vs `MultipartStreamParser.cc` | `crash-475fce340a...` / `crash-42712dc...` | Discovered via differential fuzzer |
| **Issue 05** | Malformed Header Line Premature Termination | CWE-444 | **High** | `HttpRequestParser.cc` (upstream regression) | `BadHeaderNoColon\r\n` | Patch provided (`0005-...patch`) |
| **Issue 06** | Differential Request Framing vs `llhttp` | CWE-444 | **Medium** | `HttpRequestParser.cc` vs Node.js `llhttp` | `crash-7b730c93...` (`\r\n\xfa`) | Differential test case documented |
| **Issue 07** | Response Header Null-Byte Injection | CWE-113 | **Medium** | `HttpUtils.cc` (`isValidHeader`) | `crash-1db419f7...` (`\0` in header) | Patch provided (`0007-...patch`) |

---

## 2. Directory Structure

```text
drogon-issues-and-reproducers/
├── README.md                                 # Master documentation and reproduction guide
├── reproduce_all.sh                          # Automated reproduction test runner
│
├── issue-01-httpfile-iterator-oob/           # Issue 01: Iterator OOB in HttpFileImpl::save()
│   ├── ISSUE_REPORT.md                       # Comprehensive vulnerability report
│   ├── reproduce_standalone.cc               # Standalone C++ reproducer
│   ├── reproducer_prefix_traversal.bin       # Raw 7-byte trigger payload ("../../c")
│   ├── reproducer_live_fuzzer.bin            # Raw 2-byte trigger payload ("..")
│   ├── crash_libfuzzer.log                   # LibFuzzer crash trace
│   ├── crash_standalone.log                  # Standalone execution abort trace
│   ├── test_fix_verification.cc              # Post-fix regression test suite
│   ├── verification_results.log              # Log confirming 0 crashes after fix
│   └── 0001-Fix-out-of-bounds-iterator-dereference-in-HttpFileIm.patch
│
├── issue-02-filesystem-noexcept-dos/         # Issue 02: Critical Server DoS in HttpFileImpl
│   ├── ISSUE_REPORT.md                       # Detailed incident report
│   ├── reproduce_standalone.cc               # Standalone C++ reproducer (fork/exec SIGABRT)
│   ├── crash-65e67953a3b9503f79ab1391320e2152ffed3ede # Raw 266-byte trigger file
│   ├── crash.log                             # LibFuzzer std::terminate stacktrace
│   ├── crash_original_baseline.log           # Unpatched baseline std::terminate abort evidence
│   └── 0002-fix-filesystem-noexcept-dos.patch # Complete std::error_code overload patch
│
├── issue-03-httpresponse-enum-ub/            # Issue 03: Undefined Behavior in HttpResponseParser
│   ├── ISSUE_REPORT.md                       # Detailed incident report
│   ├── reproduce_standalone.cc               # Standalone C++ reproducer
│   ├── crash-6cb7836dc05ed7fcbfb7b757ce638a9f45714d72 # Trigger payload (status code 20020)
│   ├── crash-ef6e30d1adce92e688d9bc9630f196599b0f52d2 # Trigger payload (status code 220220)
│   ├── crash-f6b81f87b869b0a3892eda681d1ab59cb9eb9b78 # Trigger payload (fragmented status)
│   ├── crash.log                             # __ubsan_handle_load_invalid_value_abort log
│   └── 0003-fix-httpresponse-enum-ub.patch   # Fixed enum underlying type & bounds patch
│
├── issue-04-multipart-streaming-desync/      # Issue 04: Multipart Differential Discrepancy
│   ├── ISSUE_REPORT.md                       # Detailed incident report
│   ├── reproduce_standalone.cc               # Standalone differential comparison harness
│   ├── crash-42712dc34fc1346a03df803cadf193b6d15439ad # Trigger artifact (part count mismatch)
│   ├── crash-475fce340a06d371706e91e7cec3ec643c753461 # Trigger artifact (parameter drop)
│   ├── crash-4a83e1cdc531b3b42c0b9078dc80fa2c1eb6a7ef # Trigger artifact (boundary injection)
│   ├── crash-89c3506e5641f1654dca59f9fc31f7fe8d32460b # Historical trigger artifact
│   └── crash.log                             # Fuzzer differential failure log
│
├── issue-05-upstream-header-framing/         # Issue 05: Malformed Header Line Termination
│   ├── ISSUE_REPORT.md                       # Detailed incident report
│   ├── reproduce_standalone.cc               # Standalone parser test
│   ├── 0005-fix-upstream-header-framing.patch # Strict line.empty() check patch
│   └── test_failure.log                      # Test log before patch
│
├── issue-06-llhttp-differential-framing/     # Issue 06: Differential Framing vs Node.js llhttp
│   ├── ISSUE_REPORT.md                       # Detailed incident report
│   ├── reproduce_standalone.cc               # Standalone parser comparison harness
│   ├── crash-7b730c93c3038fb2626e5da85bd59aa44a24c85f # Trigger artifact ("\r\n\xfa")
│   └── crash.log                             # Differential mismatch crash log
│
└── issue-07-response-builder-null-injection/ # Issue 07: Response Header Validation
    ├── ISSUE_REPORT.md                       # Detailed incident report
    ├── reproduce_standalone.cc               # Standalone validator test
    ├── crash-1db419f721702c707952f33d23033ff242cee362 # Trigger payload (embedded \0)
    ├── crash-e75db03a1fb1fe18ef442099b25b57cc496ae046 # Trigger payload (control character)
    ├── crash.log                             # Fuzzer log
    └── 0007-fix-header-validation-null-rejection.patch # isValidHeader null-byte check patch
```

---

## 3. How to Reproduce Each Defect

### Standalone Reproduction (Zero External Dependencies)
Each subfolder contains a standalone `reproduce_standalone.cc` program that can be compiled and executed directly against Drogon headers and static libraries.

To run the verification suite:
```bash
chmod +x reproduce_all.sh
./reproduce_all.sh
```

### LibFuzzer Replay
If running in an environment with the `drogon-fuzz` build binaries:
```bash
# Replay Issue 02 DoS trigger:
./build/asan/fuzz_filesystem issue-02-filesystem-noexcept-dos/crash-65e67953a3b9503f79ab1391320e2152ffed3ede

# Replay Issue 03 UBSan trigger:
./build/asan/fuzz_http_response_fragmented issue-03-httpresponse-enum-ub/crash-6cb7836dc05ed7fcbfb7b757ce638a9f45714d72

# Replay Issue 04 Multipart differential trigger:
./build/asan/fuzz_multipart_stream issue-04-multipart-streaming-desync/crash-475fce340a06d371706e91e7cec3ec643c753461

# Replay Issue 06 llhttp differential trigger:
./build/asan/fuzz_llhttp_differential issue-06-llhttp-differential-framing/crash-7b730c93c3038fb2626e5da85bd59aa44a24c85f
```
