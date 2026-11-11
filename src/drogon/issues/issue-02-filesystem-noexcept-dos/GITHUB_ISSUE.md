**Notice**
If you need support or clarification regarding the usage of Drogon in your project, visit the official Drogon support channel at [gitter](https://gitter.im/drogon-web/community)

Please create a new issue only if you think you have found a bug or if have a feature request/enhancement.

**Describe the bug**
In `lib/src/HttpFileImpl.cc`, `HttpFileImpl::save()`, `HttpFileImpl::save(const std::string &path)`, and `HttpFileImpl::saveAs(const std::string &fileName)` are declared `noexcept`, but invoke throwing overloads of standard filesystem functions (`std::filesystem::current_path()`, `std::filesystem::weakly_canonical()`, and `std::filesystem::exists()`) without passing `std::error_code`.

When an upload filename component exceeds the operating system limit (`NAME_MAX`, typically 255 bytes on Linux/Unix systems) or when underlying filesystem queries fail (e.g., due to permission errors or traversing through a regular file as a directory), `std::filesystem` functions throw `std::filesystem_error`. Because these methods are marked `noexcept`, the uncaught exception escaping the `noexcept` boundary triggers `std::terminate()`, aborting the process with `SIGABRT`.

A remote client may trigger process termination in applications that expose multipart uploads and call `HttpFile::save()` or `HttpFile::saveAs()` on request-controlled paths without validating them.

**To Reproduce**
Steps to reproduce the behavior:
1. Define a Drogon endpoint accepting multipart file uploads (similar to the standard upload example in the Drogon documentation) that saves the uploaded file:
   ```cpp
   app().registerHandler("/upload", [](const HttpRequestPtr &req,
                                       std::function<void(const HttpResponsePtr &)> &&callback) {
       MultiPartParser parser;
       if (parser.parse(req) == 0) {
           for (const auto &file : parser.getFiles()) {
               file.save(); // or file.saveAs(file.getFileName())
           }
       }
       auto resp = HttpResponse::newHttpResponse();
       callback(resp);
   }, {Post});
   ```
2. Upload a file via a `multipart/form-data` request where the `filename` parameter in the `Content-Disposition` header contains a path component exceeding 255 characters (e.g., `Content-Disposition: form-data; name="file"; filename="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"`).
3. The server handler invokes `file.save()`.
4. Observe immediate crash / abort with `SIGABRT` and the following diagnostic message on stderr:
   ```text
   terminate called after throwing an instance of 'std::filesystem::__cxx11::filesystem_error'
     what(): filesystem error: status: File name too long [/path/to/uploads/aaaa...]
   Aborted (core dumped)
   ```

A minimal standalone C++ reproducer:
```cpp
#include <drogon/HttpAppFramework.h>
#include "../../lib/src/HttpFileImpl.h"
#include <iostream>
#include <string>

int main() {
    drogon::HttpFileImpl file;
    // Filename component exceeding NAME_MAX (255)
    std::string longFileName(300, 'x');
    file.setFileName(longFileName);
    file.setFile("test payload", 12);

    // save() is marked noexcept, but weakly_canonical() throws std::filesystem_error
    // Causes immediate std::terminate()
    file.save("./uploads");
    return 0;
}
```

**Expected behavior**
File-saving operations should handle filesystem errors gracefully without throwing uncaught exceptions or terminating the process. On any filesystem failure (invalid filename, excessive component length, permission error, or inaccessible parent path), `HttpFileImpl::save()` and `HttpFileImpl::saveAs()` should log an informative error message and return `-1` to the caller, allowing the application to handle the failure and respond appropriately (e.g., with HTTP 400 Bad Request or HTTP 500 Internal Server Error).

**Screenshots**
N/A (Console crash trace provided in Additional context).

**Desktop (please complete the following information):**
 - OS: Linux (Ubuntu 22.04 LTS / 24.04 LTS x86_64), POSIX environments with `NAME_MAX` limits
 - Browser: N/A (Backend server framework)
 - Version: Drogon `master` (and release versions up to 1.9.9 / 1.9.14)

**Smartphone (please complete the following information):**
 - Device: N/A
 - OS: N/A
 - Browser: N/A
 - Version: N/A

**Additional context**
1. **Root Cause Analysis:**
   - In `lib/src/HttpFileImpl.cc`:
     - `std::filesystem::current_path()` is called without `std::error_code`.
     - `std::filesystem::weakly_canonical()` is called twice without `std::error_code` (on `fsUploadDir` and on `fsUploadDir / utils::toNativePath(fileName_)`).
     - `std::filesystem::exists()` is called without `std::error_code`.
   - While `std::filesystem::create_directories(..., err)` already passed `err`, query operations like `exists()` and canonicalization operations threw unhandled `std::filesystem_error` exceptions before reaching directory creation.
   - Furthermore, `if (!std::filesystem::exists(fsUploadDir))` conflated query errors with directory non-existence.
2. **Crash Stack Trace (captured under AddressSanitizer):**
   ```text
   terminate called after throwing an instance of 'std::filesystem::__cxx11::filesystem_error'
     what(): filesystem error: status: File name too long [...]
   ==1559== ERROR: libFuzzer: deadly signal
       #0 in __sanitizer_print_stack_trace
       #1 in fuzzer::PrintStackTrace()
       #2 in fuzzer::Fuzzer::CrashCallback()
       #3 in libc.so.6
       #4 in pthread_kill
       #5 in raise
       #6 in abort
       #7 in libstdc++.so.6
       #8 in libstdc++.so.6
       #9 in std::terminate()
       #10 in __clang_call_terminate
       #11 in drogon::HttpFileImpl::save(std::string const&) const lib/src/HttpFileImpl.cc:68
   ```
3. **Proposed Fix & Pull Request:**
   A pull request is ready that:
   - Replaces the throwing filesystem overloads of `current_path`, `weakly_canonical`, and `exists` with `std::error_code` overloads.
   - Makes filesystem error handling consistent across the existing `create_directories` calls.
   - Separates filesystem query failures from directory existence checks so errors are reported without attempting invalid directory creations.
   - Preserves Drogon's exact upload path resolution semantics (resolving relative paths against `getUploadPath()` unless prefixed with `./` or `../`).
   - Adds unit tests to `lib/tests/unittests/HttpFileTest.cc` exercising runtime component length limits via `pathconf(..., _PC_NAME_MAX)`, parent path traversal beneath regular files (`ENOTDIR`), excessive parent path resolution in `saveAs()`, and standard relative directory uploads.

