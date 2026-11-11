# Issue 02: Uncaught std::filesystem Exceptions Inside noexcept Methods (Application-Dependent Denial of Service)

## Metadata
- **Vulnerability Type:** Application-Dependent Denial of Service / Exception Safety Violation in `noexcept` Methods
- **CWE:** CWE-755 (Improper Handling of Exceptional Conditions) / CWE-248 (Uncaught Exception)
- **Severity:** Medium / High (Application-dependent process termination)
- **Location:** `lib/src/HttpFileImpl.cc`
- **Affected Functions:**
  - `int HttpFileImpl::save() const noexcept`
  - `int HttpFileImpl::save(const std::string &path) const noexcept`
  - `int HttpFileImpl::saveAs(const std::string &fileName) const noexcept`
- **Discovery Method:** `fuzz_filesystem` LibFuzzer target in `drogon-fuzz`.
- **Reproducer Artifact:** `crash-65e67953a3b9503f79ab1391320e2152ffed3ede` (266 bytes)
- **Standalone Reproducer:** `reproduce_standalone.cc`
- **Baseline Crash Evidence:** `crash_original_baseline.log` (captured against unpatched commit `554f333b`)
- **Fix Patch:** `0002-fix-filesystem-noexcept-dos.patch`

---

## 1. Vulnerability Mechanics

In `drogon/lib/src/HttpFileImpl.cc`, file saving operations are explicitly declared `noexcept`:
```cpp
int HttpFileImpl::save() const noexcept
int HttpFileImpl::save(const std::string &path) const noexcept
int HttpFileImpl::saveAs(const std::string &fileName) const noexcept
```

Within these methods, the original implementation invoked throwing overloads of standard filesystem functions:
```cpp
fsUploadDir = std::filesystem::weakly_canonical(fsUploadDir);

if (!std::filesystem::exists(fsUploadDir))
{
    // ...
}

std::filesystem::path fsSaveToPath(std::filesystem::weakly_canonical(
    fsUploadDir / utils::toNativePath(fileName_)));
```

### The Failure Mode
1. An operating-system filesystem error (such as a filename component exceeding `NAME_MAX`, invalid path characters, or permission/inaccessible path errors) causes `std::filesystem` functions without `std::error_code` to throw `std::filesystem::filesystem_error`.
2. Under the ISO C++ standard, if an exception escapes a function marked `noexcept`, the C++ runtime immediately invokes `std::terminate()`.
3. `std::terminate()` aborts the entire server process with `SIGABRT` (deadly signal 6), dropping all active client connections and killing the service.

---

## 2. Realistic Impact & Reachability Assessment

- **Trigger:** A multipart upload request containing an upload filename with an excessively long path component ($> 255\text{ bytes}$ on ext4/tmpfs) or an invalid/inaccessible path structure.
- **Reachability:** Drogon does not automatically save every uploaded file to disk. However, typical application file-upload handlers (including Drogon's own official file-upload documentation and examples) explicitly call `file.save()` or `file.saveAs()`.
- **Impact Statement:** **A remote client may trigger process termination in applications that expose multipart uploads and call `HttpFile::save()` or `HttpFile::saveAs()` on request-controlled paths without validating them.**

---

## 3. Crash Evidence & Stack Trace

### LibFuzzer Crash Log (`crash.log`)
```text
terminate called after throwing an instance of 'std::filesystem::__cxx11::filesystem_error'
  what():  filesystem error: status: File name too long [/tmp/drogon_fs_1559/nested/uploads/ttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttppppppppppppppppppppppppppppppppppppppppppppppppppppppttttttttttttttvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv]
==1559== ERROR: libFuzzer: deadly signal
    #0 0x6228cd7e2665 in __sanitizer_print_stack_trace
    #1 0x6228cd73c17c in fuzzer::PrintStackTrace()
    #2 0x6228cd722207 in fuzzer::Fuzzer::CrashCallback()
    #3 0x7fd299c4532f in libc.so.6
    #4 0x7fd299c9ec0b in pthread_kill
    #5 0x7fd299c4527d in raise
    #6 0x7fd299c288fe in abort
    #7 0x7fd29a8a5ff4 in libstdc++.so.6
    #8 0x7fd29a8bb0d9 in libstdc++.so.6
    #9 0x7fd29a8a5a54 in std::terminate()
    #10 0x6228cd8217dd in __clang_call_terminate
    #11 0x6228cd94d8d3 in drogon::HttpFileImpl::save(const std::string&) const drogon/lib/src/HttpFileImpl.cc:68
```

### Unpatched Baseline Reproducer Output (`crash_original_baseline.log`)
```text
[*] Investigating unhandled std::filesystem_error in noexcept HttpFileImpl::save()...
    Target: drogon::HttpFileImpl::save(const std::string &path) const noexcept

--- Child Process Diagnostic ---
terminate called after throwing an instance of 'std::filesystem::__cxx11::filesystem_error'

[!] RESULT: Child terminated with deadly signal 6 (Aborted)
[+] CONFIRMED: std::terminate() invoked due to uncaught std::filesystem_error in noexcept method!
    A remote client may trigger process termination in applications that expose multipart
    uploads and call HttpFile::save() or HttpFile::saveAs() on request-controlled paths without validating them.
```

---

## 4. Remediation & Error-Handling Discipline

The patch applies comprehensive error-handling discipline across all filesystem interactions:
1. **Preserving Upload-Path Resolution Semantics:** Drogon's distinction between absolute paths, ordinary relative paths resolved against `app().getUploadPath()`, and `./` or `../` paths resolved against the current directory is preserved. `current_path(ec)` is called strictly within the `./` or `../` branch.
2. **Separating Directory Existence from Query Failures:** `std::filesystem::exists(dir, ec)` is evaluated; if `ec` is set (e.g. permission or status error), an error is logged and `-1` returned immediately without attempting directory creation.
3. **No-Throw `ec` Overloads:** Replaced the throwing filesystem overloads of `current_path`, `weakly_canonical` and `exists` with error-code overloads. Also made filesystem error handling consistent across the existing `create_directories` calls.

```cpp
    std::error_code ec;
    if (fsUploadDir.is_absolute())
    {  // do nothing
    }
    else if (!fsUploadDir.has_parent_path() ||
             (fsUploadDir.begin()->string() != "." &&
              fsUploadDir.begin()->string() != ".."))
    {
        fsUploadDir =
            std::filesystem::path(
                HttpAppFrameworkImpl::instance().getUploadPath()) /
            fsUploadDir;
    }
    else
    {
        auto curPath = std::filesystem::current_path(ec);
        if (ec)
        {
            LOG_ERROR << "Failed to get current path: " << ec.message();
            return -1;
        }
        fsUploadDir = curPath / fsUploadDir;
    }

    fsUploadDir = std::filesystem::weakly_canonical(fsUploadDir, ec);
    if (ec)
    {
        LOG_ERROR << "Failed to canonicalize upload directory: " << ec.message();
        return -1;
    }

    const bool directoryExists = std::filesystem::exists(fsUploadDir, ec);
    if (ec)
    {
        LOG_ERROR << "Failed to check upload directory: " << ec.message();
        return -1;
    }

    if (!directoryExists)
    {
        LOG_TRACE << "create path:" << fsUploadDir;
        std::filesystem::create_directories(fsUploadDir, ec);
        if (ec)
        {
            LOG_ERROR << "Failed to create upload directory: " << ec.message();
            return -1;
        }
    }

    std::filesystem::path fsSaveToPath = std::filesystem::weakly_canonical(
        fsUploadDir / utils::toNativePath(fileName_), ec);
    if (ec)
    {
        LOG_ERROR << "Failed to canonicalize save path: " << ec.message();
        return -1;
    }
```

And in `saveAs(fileName)`:
```cpp
    if (fsFileName.has_parent_path())
    {
        std::error_code ec;
        const bool parentExists =
            std::filesystem::exists(fsFileName.parent_path(), ec);
        if (ec)
        {
            LOG_ERROR << "Failed to check parent directory: " << ec.message();
            return -1;
        }
        if (!parentExists)
        {
            LOG_TRACE << "create path:" << fsFileName.parent_path();
            std::filesystem::create_directories(fsFileName.parent_path(), ec);
            if (ec)
            {
                LOG_ERROR << "Failed to create directory: " << ec.message();
                return -1;
            }
        }
    }
    return saveTo(fsFileName);
```

---

## 5. Verification Test Suite

Tests added to `lib/tests/unittests/HttpFileTest.cc`:
- **`getPathComponentLimit()`:** Portable helper querying `::pathconf(..., _PC_NAME_MAX)` on an existing directory (`filesystem::current_path()`, with fallback to `NAME_MAX`/255).
- **`FilenameExceedingNameMax`:** Verifies filename exceeding OS limit returns `-1` without throwing.
- **`SaveAsWithExcessiveParentDirectory`:** Places excessive component in `parent_path` (`uploadPath / longDir / "upload.bin"`), directly exercising `exists(parent, ec)`.
- **`SavePathWithNormalRelativePath`:** Verifies ordinary relative path without `.` or `..` resolves against `app().getUploadPath()` (with RAII guard restoring original path).
- **`RelativePathCurrentPathBranch`:** Verifies `./` relative paths exercise `current_path(ec)` successfully.
- **`SaveAsInaccessibleParentDirectory`:** Uses a destination whose parent path traverses through an existing regular file. Verifies that the resulting `ENOTDIR` filesystem error is handled gracefully and `saveAs()` returns `-1`.
- **`UploadPathIsRegularFile`:** Verifies upload directory pointing to a regular file returns `-1` gracefully.
