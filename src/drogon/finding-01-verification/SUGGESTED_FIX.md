# Suggested Fix: Out-of-Bounds Iterator Dereference in HttpFileImpl::save()

## 1. Vulnerability Summary
- **Target File:** `drogon/lib/src/HttpFileImpl.cc` (line 71)
- **Target Method:** `int HttpFileImpl::save(const std::string &path) const noexcept`
- **Defect Class:** Out-of-bounds Iterator Dereference / Precondition Violation
- **Standard Reference:** ISO/IEC 14882:2017 (C++17) Section `[alg.equal]`

---

## 2. Root Cause Analysis

In `HttpFileImpl.cc`:
```cpp
int HttpFileImpl::save(const std::string &path) const noexcept
{
    ...
    std::filesystem::path fsSaveToPath(std::filesystem::weakly_canonical(
        fsUploadDir / utils::toNativePath(fileName_)));
    LOG_TRACE << "save to path:" << fsSaveToPath;
    if (!std::equal(fsUploadDir.begin(),
                    fsUploadDir.end(),
                    fsSaveToPath.begin())) // <-- Precondition Violation
    {
        LOG_ERROR
            << "Attempt writing outside of upload directory detected. Path: "
            << fileName_;
        return -1;
    }
```

### The C++ Standard Requirement
The 3-iterator overload of `std::equal`:
```cpp
template<class InputIterator1, class InputIterator2>
bool equal(InputIterator1 first1, InputIterator1 last1, InputIterator2 first2);
```
requires that `[first2, first2 + (last1 - first1))` is a valid range. That is, the second sequence must contain at least as many elements as the first sequence.

### How the Bug Triggers
When untrusted user input contains directory traversal sequences (such as `..` or `../../c`), `std::filesystem::weakly_canonical` resolves `fsSaveToPath` to an ancestor path that has **fewer components** than `fsUploadDir`:
- `fsUploadDir`:  `/tmp/uploads/a/b/c` (5 components: `/`, `tmp`, `uploads`, `a`, `b`, `c`)
- `fsSaveToPath`: `/tmp/uploads/a/b` (4 components)

When `std::equal` executes:
1. It compares component 1 (`/` == `/`): matches.
2. It compares component 2 (`tmp` == `tmp`): matches.
3. It compares component 3 (`uploads` == `uploads`): matches.
4. It compares component 4 (`a` == `a`): matches.
5. It attempts to advance and dereference the 5th component of `fsSaveToPath` — but `fsSaveToPath` only has 4 components!
6. It dereferences past `fsSaveToPath.end()`.

Under `_GLIBCXX_ASSERTIONS` / `_GLIBCXX_DEBUG` (and standard debug builds), libstdc++ traps with:
```text
Assertion '_M_cur != _M_path->_M_cmpts.end()' failed.
```
and raises `SIGABRT`, immediately terminating the web server.

---

## 3. Evaluated Fix Approaches

### Approach A: 4-iterator `std::equal` (INCORRECT)
```cpp
// INCORRECT:
if (!std::equal(fsUploadDir.begin(), fsUploadDir.end(),
                fsSaveToPath.begin(), fsSaveToPath.end()))
```
*Why this fails:* 4-iterator `std::equal` requires both sequences to have the **exact same number of elements**. If an uploaded file is saved to a legitimate nested subdirectory (e.g. `uploadDir / "images" / "avatar.png"`), the component count is larger than `uploadDir`. 4-iterator `std::equal` would return `false` and mistakenly reject valid descendant files!

### Approach B: 4-iterator `std::mismatch` (RECOMMENDED & CORRECT)
```cpp
// CORRECT:
auto mismatch = std::mismatch(fsUploadDir.begin(),
                              fsUploadDir.end(),
                              fsSaveToPath.begin(),
                              fsSaveToPath.end());
if (mismatch.first != fsUploadDir.end())
{
    LOG_ERROR << "Attempt writing outside of upload directory detected. Path: " << fileName_;
    return -1;
}
```
*Why this is optimal:*
1. **Bounds both ranges:** It stops as soon as either `fsUploadDir` or `fsSaveToPath` reaches its `end()`. It is mathematically impossible to dereference past either sequence.
2. **True prefix check:** `mismatch.first == fsUploadDir.end()` is true if and only if `fsUploadDir` is a complete prefix of `fsSaveToPath`.
   - If `fsSaveToPath` has fewer components (e.g. `../../c`), `mismatch.second` hits `end()` early, so `mismatch.first != fsUploadDir.end()`, returning `-1` cleanly.
   - If `fsSaveToPath` diverges to another path (e.g. `/etc/passwd`), mismatch occurs early, returning `-1` cleanly.
   - If `fsSaveToPath` is a legitimate file or subdirectory inside `fsUploadDir`, `mismatch.first == fsUploadDir.end()`, allowing the write to proceed safely.

---

## 4. Git Patch

```diff
diff --git a/lib/src/HttpFileImpl.cc b/lib/src/HttpFileImpl.cc
index 57323ca3..83a3144b 100644
--- a/lib/src/HttpFileImpl.cc
+++ b/lib/src/HttpFileImpl.cc
@@ -68,9 +68,11 @@ int HttpFileImpl::save(const std::string &path) const noexcept
     std::filesystem::path fsSaveToPath(std::filesystem::weakly_canonical(
         fsUploadDir / utils::toNativePath(fileName_)));
     LOG_TRACE << "save to path:" << fsSaveToPath;
-    if (!std::equal(fsUploadDir.begin(),
-                    fsUploadDir.end(),
-                    fsSaveToPath.begin()))
+    auto mismatch = std::mismatch(fsUploadDir.begin(),
+                                  fsUploadDir.end(),
+                                  fsSaveToPath.begin(),
+                                  fsSaveToPath.end());
+    if (mismatch.first != fsUploadDir.end())
     {
         LOG_ERROR
             << "Attempt writing outside of upload directory detected. Path: "
```

To apply:
```bash
git apply 0001-Fix-out-of-bounds-iterator-dereference-in-HttpFileImpl-save.patch
```

