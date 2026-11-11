# Finding 02: Unhandled std::filesystem Exceptions in noexcept File-Save Methods

## Summary
- **Target File:** `drogon/lib/src/HttpFileImpl.cc` (lines 48, 51, 53, 67, 99)
- **Target Methods:**
  - `int HttpFileImpl::save() const noexcept`
  - `int HttpFileImpl::save(const std::string &path) const noexcept`
  - `int HttpFileImpl::saveAs(const std::string &fileName) const noexcept`
- **Defect Class:** Exception Safety / Potential `noexcept` Termination on `std::filesystem::filesystem_error`
- **Severity:** Medium (Source-Audit Candidate)
- **Status:** Source-Audit Candidate (Theoretical DoS on OS-level Filesystem / Permission Errors)

## Vulnerability Mechanics
In `HttpFileImpl.cc`, multiple file saving methods are declared `noexcept`:
```cpp
int HttpFileImpl::save(const std::string &path) const noexcept
```
Within these methods, several throwing overloads of `std::filesystem` functions are invoked without `std::error_code`:
1. `std::filesystem::current_path()`: Invoked without `std::error_code`. Throws `std::filesystem_error` if current working directory has been unlinked or is inaccessible.
2. `std::filesystem::weakly_canonical(...)`: Invoked without `std::error_code` at lines 51 and 67. Can throw `std::filesystem_error` on permission failure (`EACCES`), symlink cycles (`ELOOP`), or filesystem I/O errors.
3. `std::filesystem::exists(...)`: Invoked without `std::error_code` at lines 53 and 99. Throws `std::filesystem_error` on permission failure traversing parent directories.

Because the enclosing functions are marked `noexcept`, any thrown `std::filesystem_error` invokes `std::terminate()`, terminating the server process.

## Exploitability & Reachability Assessment
- **Assessment:** Source-audit candidate. Under standard production deployment permissions, standard upload paths are typically accessible and writable. Inducing a throw generally requires controlled filesystem faults (e.g. symlink loop creation, permission revocation during execution, or disk failure). Remote reachability via pure HTTP requests without local filesystem access remains unconfirmed.

## Defensive Remediation
Use the standard non-throwing overloads accepting `std::error_code &ec`:
```cpp
std::error_code ec;
fsUploadDir = std::filesystem::weakly_canonical(fsUploadDir, ec);
if (ec)
{
    LOG_ERROR << "Failed to resolve path: " << ec.message();
    return -1;
}
```
Or encapsulate operations in `try { ... } catch (const std::exception &e) { LOG_ERROR << e.what(); return -1; }` before returning from `noexcept` methods.
