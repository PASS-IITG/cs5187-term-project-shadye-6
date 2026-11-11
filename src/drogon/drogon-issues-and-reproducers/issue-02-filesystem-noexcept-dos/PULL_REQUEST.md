# PR #2662: fix(httpfile): handle filesystem errors safely in noexcept save methods (#2661)

- **Issue:** [#2661](https://github.com/drogonframework/drogon/issues/2661)
- **Pull Request:** [#2662](https://github.com/drogonframework/drogon/pull/2662)
- **Branch:** `shadye-6:bugfix/2661-fix-httpfile-noexcept-filesystem-exceptions`
- **Target:** `drogonframework:master`
- **Status:** Open

---

Fixes #2661.

## Description

`HttpFileImpl::save()`, `HttpFileImpl::save(const std::string &path)`, and `HttpFileImpl::saveAs(const std::string &fileName)` are declared `noexcept`, but their original implementations invoked throwing overloads of standard filesystem functions, including `std::filesystem::current_path()`, `std::filesystem::weakly_canonical()`, and `std::filesystem::exists()` without passing an `std::error_code`.

When an upload filename component exceeds the operating system's filesystem component-name limit (`NAME_MAX`, typically 255 bytes on Linux filesystems), or when an underlying filesystem query fails, these operations can throw `std::filesystem::filesystem_error`.

Because the exceptions escape methods declared `noexcept`, the C++ runtime invokes `std::terminate()`, aborting the application process with `SIGABRT`.

This creates an application-dependent denial-of-service condition when an application exposes multipart uploads and calls `HttpFile::save()` or `HttpFile::saveAs()` using request-controlled paths.

### Changes Made

1. **Replaced throwing filesystem overloads:** Replaced the throwing overloads of `current_path()`, `weakly_canonical()`, and `exists()` with their `std::error_code` counterparts.
2. **Consistent directory-creation error handling:** Made error checking and logging consistent across the existing `create_directories()` calls in `save()` and `saveAs()`.
3. **Separated query failures from existence checks:** Filesystem query errors are now handled separately from directory non-existence. This avoids treating an unsuccessful filesystem query as an ordinary missing directory.
4. **Preserved upload-path resolution semantics:**
   - Absolute paths remain unchanged.
   - Ordinary relative paths resolve against the configured upload directory.
   - Relative paths beginning with `./` or `../` use the current-working-directory resolution branch.
5. **Graceful error returns:** Filesystem errors are logged and reported through a `-1` return value rather than allowing filesystem exceptions to terminate the process.

---

## Unit Tests

Added `DROGON_TEST(HttpFileExceptionSafety)` in `lib/tests/unittests/HttpFileTest.cc`, covering:
- **`FilenameExceedingNameMax`:** Uses the runtime filesystem component-name limit to verify that an excessively long filename is rejected gracefully.
- **`SaveAsWithExcessiveParentDirectory`:** Uses an oversized parent-directory component to exercise the `exists(parent, ec)` error-handling path in `saveAs()`.
- **`SavePathWithNormalRelativePath`:** Verifies that an ordinary relative path resolves against the configured upload directory (with an RAII guard restoring `app().getUploadPath()`).
- **`RelativePathCurrentPathBranch`:** Verifies that paths beginning with `./` use the current-working-directory resolution branch.
- **`SaveAsInaccessibleParentDirectory`:** Uses a destination whose parent path traverses through an existing regular file. Verifies that the resulting `ENOTDIR` filesystem error is handled gracefully and `saveAs()` returns `-1`.
- **`UploadPathIsRegularFile`:** Verifies that attempting to use a regular file as an upload directory fails gracefully.

---

## Verification

The exception-safety regression tests and permanent regression replay suite passed locally. Sanitizer and compiler configurations used for verification are documented below:

- **Baseline Reproduction:** Reproducer process reproduced `std::terminate()` on the unpatched Drogon implementation (`554f333b`).
- **Patched Verification:** Patched implementation handles the filesystem failures cleanly without terminating (returns `-1`).
- **Regression Replay:** All 11 dedicated `HttpFile` regression/exception-safety checks and all 13 permanent regression replay targets passed.
- **API Stability:** No changes to public API or function signatures.

**Verification Environment:**
- Compiler: Clang 18.1.3 (`-std=c++17`)
- Standard Library: GNU `libstdc++ 13`
- Sanitizers: AddressSanitizer (`-fsanitize=address`) and UndefinedBehaviorSanitizer (`-fsanitize=undefined`)
- Target: Linux x86_64 (Ubuntu 24.04 LTS / POSIX)

---

## Checklist
- [x] My code follows the Google C++ style guidelines of this project
- [x] Modified files formatted using the repository `.clang-format` configuration
- [x] I have added unit tests that verify the bugfix
- [x] All existing and new tests pass locally
- [x] No breaking changes to public API
