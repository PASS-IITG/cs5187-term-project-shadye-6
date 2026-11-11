# Finding 01 Verification Package: Out-of-Bounds Iterator Dereference in Drogon

This package contains everything required to reproduce, analyze, and verify the fix for **Finding 01** in the Drogon C++ Framework.

---

## 1. Package Contents

| File | Description |
| :--- | :--- |
| `reproducer_live_fuzzer.bin` | The exact 2-byte crash input generated during Stage 3 libFuzzer execution (`..` / `0x2e, 0x2e`). |
| `reproducer_prefix_traversal.bin` | The deterministic test input (`../../c`) that generates strictly fewer path components than the upload root. |
| `reproduce_standalone.cc` | Self-contained C++ reproduction harness isolating the out-of-bounds dereference in a child process with stderr diagnostic capture. |
| `crash_libfuzzer.log` | Raw crash output from `fuzz_filesystem` running inside the Bubblewrap sandbox. |
| `crash_standalone.log` | Raw assertion and diagnostic log captured from `reproduce_standalone.cc`. |
| `0001-Fix-out-of-bounds-iterator-dereference-in-HttpFileImpl-save.patch` | Clean unified git patch ready to apply to Drogon `master`. |
| `SUGGESTED_FIX.md` | Comprehensive technical write-up detailing the vulnerability mechanics, ISO C++ standard violation, and why `std::mismatch` is the optimal fix. |

---

## 2. Vulnerability Summary

- **File:** `drogon/lib/src/HttpFileImpl.cc` (line 71)
- **Method:** `int HttpFileImpl::save(const std::string &path) const noexcept`
- **Defect:** 3-iterator `std::equal(fsUploadDir.begin(), fsUploadDir.end(), fsSaveToPath.begin())` violates ISO C++17 `[alg.equal]` preconditions when `fsSaveToPath` has fewer path components than `fsUploadDir`.
- **Severity:** High (Denial of Service / Process Abort via untrusted multipart file uploads)
- **Upstream Status:** Live on `master` at commit `df418bfdd99d4cc1ebd8598b8ced4f74d4f488ce`.

---

## 3. How to Reproduce

### Method A: Standalone C++ Test Harness (Recommended)

1. Navigate to the verification directory:
   ```bash
   cd finding-01-verification
   ```

2. Compile `reproduce_standalone.cc` against Drogon in your environment (with `_GLIBCXX_ASSERTIONS` enabled, or under Clang/GCC debug mode):
   ```bash
   clang++ -O1 -g -D_GLIBCXX_ASSERTIONS reproduce_standalone.cc \
       -I/path/to/drogon/lib/inc \
       -I/path/to/drogon/trantor \
       -L/path/to/drogon/build \
       -ldrogon -ltrantor -ljsoncpp -luuid -lz -lssl -lcrypto \
       -o test_repro
   ```

3. Run the binary:
   ```bash
   ./test_repro
   ```

4. Expected Output:
   ```text
   [*] Investigating candidate Undefined Behavior in HttpFileImpl::save()...
       Target: 3-iterator std::equal(fsUploadDir.begin(), fsUploadDir.end(), fsSaveToPath.begin())
       fsUploadDir:  "/tmp/drogon_ub_test_XXXX/a/b/c/upload" (7 components)
       fsSaveToPath: "/tmp/drogon_ub_test_XXXX/a/b/c" (6 components)
       [!] Condition verified: Destination path has FEWER components than upload root!
       Captured child stderr:
   bits/fs_path.h:1398: path::iterator::reference std::filesystem::path::iterator::operator*() const: Assertion '_M_cur != _M_path->_M_cmpts.end()' failed.

       [CONFIRMED DEFECT] Child process aborted with signal 6 and libstdc++ past-end iterator assertion confirmed!
   ```

---

### Method B: Live Replay in libFuzzer Target

If you have built the `fuzz_filesystem` harness:
```bash
./fuzz_filesystem reproducer_live_fuzzer.bin
```
The fuzzer will immediately abort with `SIGABRT` and print the deadly signal stack trace matching `crash_libfuzzer.log`.

---

## 4. How to Verify the Suggested Fix

1. In your Drogon checkout, apply the patch:
   ```bash
   cd /path/to/drogon
   git apply /path/to/finding-01-verification/0001-Fix-out-of-bounds-iterator-dereference-in-HttpFileImpl-save.patch
   ```

2. Recompile Drogon and rerun `./test_repro` or `./fuzz_filesystem reproducer_live_fuzzer.bin`.

3. The function will now cleanly detect traversal, log:
   ```text
   Attempt writing outside of upload directory detected. Path: ..
   ```
   and return `-1` without crashing or dereferencing past-the-end iterators.

