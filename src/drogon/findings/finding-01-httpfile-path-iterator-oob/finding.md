# Finding 01: Out-of-Bounds Iterator Dereference in HttpFileImpl::save()

## Summary
- **Target File:** `drogon/lib/src/HttpFileImpl.cc` (line 71)
- **Target Method:** `int HttpFileImpl::save(const std::string &path) const noexcept`
- **Defect Class:** Out-of-bounds Iterator Dereference / Precondition Violation
- **Severity:** High (Denial of Service / Process Abort via untrusted multipart upload filename)
- **Status:** Independently Confirmed and Discovered Live in `fuzz_filesystem` under Bubblewrap sandbox (`crash-9d891e731f75deae56884d79e9816736b7488080`) and verified via Standalone Harness (`test_httpfile_save_ub`)

## Vulnerability Mechanics
In `HttpFileImpl::save(const std::string &path)`:
```cpp
    std::filesystem::path fsSaveToPath(std::filesystem::weakly_canonical(
        fsUploadDir / utils::toNativePath(fileName_)));
    LOG_TRACE << "save to path:" << fsSaveToPath;
    if (!std::equal(fsUploadDir.begin(),
                    fsUploadDir.end(),
                    fsSaveToPath.begin()))
    {
        LOG_ERROR
            << "Attempt writing outside of upload directory detected. Path: "
            << fileName_;
        return -1;
    }
```
The comparison uses the legacy 3-iterator overload of `std::equal`:
`std::equal(InputIterator1 first1, InputIterator1 last1, InputIterator2 first2)`

Under C++14/17 standard specifications (`[alg.equal]`), the 3-iterator overload requires the second range beginning at `first2` to contain at least as many elements as `[first1, last1)`.

If untrusted input (e.g. `fileName_` containing traversal components such as `../../c`) resolves via `weakly_canonical` to a path `fsSaveToPath` that has fewer path components than `fsUploadDir`, and its components match the prefix of `fsUploadDir`, `std::equal` iterates past `fsSaveToPath.end()` and dereferences it.

*Note on libstdc++ 14 behavior:* A simple filename of `".."` resolves via `weakly_canonical` with a trailing directory separator, which libstdc++ 14's `path::iterator` represents as a trailing empty component (yielding the same component count as `uploadDir`). In contrast, a traversal such as `"../../c"` resolves to the parent directory component without a trailing separator, resulting in strictly fewer path components (`N - 1` vs `N`). When `std::equal` attempts to compare the N-th component, it dereferences past `fsSaveToPath.end()`.

## Reproduction & Verification
1. Replayed with `test_httpfile_save_ub` under `_GLIBCXX_DEBUG`:
   - Configured upload root: `tempBase/a/b/c/upload` (6 components: `tmp`, `drogon_ub_test`, `a`, `b`, `c`, `upload`)
   - Filename input: `../../c` -> resolves to `tempBase/a/b/c` (5 components, strict prefix)
   - Diagnostic emitted to child stderr:
     `Error: attempt to dereference a past-end iterator.`
   - Child process aborts with `SIGABRT` (signal 6).
2. Reproduction artifact: `crash_repro.bin` containing `../../c`.
3. Live Fuzzer Reproduction in Stage 3:
   - Executed `fuzz_filesystem` inside Bubblewrap sandbox (`scripts/run_filesystem_sandbox.sh`).
   - Trigger Input: `crash-9d891e731f75deae56884d79e9816736b7488080` (raw traversal `..`).
   - Diagnostic:
     ```
     bits/fs_path.h:1398:2: std::filesystem::__cxx11::path::iterator::operator*() const: Assertion '__dereferenceable' failed.
     drogon::HttpFileImpl::save(const std::string&) const HttpFileImpl.cc:71:10
     ```
   - Proves reachability from untrusted upload filenames during live fuzzing.

## Defensive Remediation
Use the 4-iterator overload of `std::mismatch` (C++14/C++17) to verify that the upload directory is a valid component-prefix of the destination path:
```cpp
    auto mismatch = std::mismatch(
        fsUploadDir.begin(), fsUploadDir.end(),
        fsSaveToPath.begin(), fsSaveToPath.end());

    if (mismatch.first != fsUploadDir.end())
    {
        LOG_ERROR
            << "Attempt writing outside of upload directory detected. Path: "
            << fileName_;
        return -1;
    }
```
*Note:* Do not use 4-iterator `std::equal` here, because 4-iterator `std::equal` requires both sequences to have identical lengths, which would mistakenly reject valid descendant files and subdirectories located inside `uploadDir`. `std::mismatch` correctly permits descendants while safely rejecting destinations shorter than `uploadDir` without out-of-bounds iterator traversal.
