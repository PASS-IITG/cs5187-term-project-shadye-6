# Issue 07: Response Builder Header Validation & Null-Byte Injection Rejection

## Metadata
- **Vulnerability Type:** HTTP Response Splitting / Null Byte Injection
- **CWE:** CWE-113 (Improper Neutralization of CRLF Sequences / Null Bytes in HTTP Headers)
- **Severity:** Medium
- **Component:** `drogon/lib/src/HttpUtils.cc` (`isValidHeader`) & `drogon/lib/src/HttpResponseImpl.cc`
- **Reproducer Artifacts:**
  - `crash-1db419f721702c707952f33d23033ff242cee362`
  - `crash-e75db03a1fb1fe18ef442099b25b57cc496ae046`

---

## 1. Vulnerability Mechanics

RFC 9110 Section 5.1 specifies:
> "A field value MUST NOT contain null (0x00) or control characters... When transmitting or receiving, a sender or recipient MUST treat null characters in field values as fatal protocol errors."

In `HttpUtils.cc`, `isValidHeader` originally checked only for `\r` and `\n`:
```cpp
bool isValidHeader(const std::string &field, const std::string &value)
{
    for (char c : field) if (c == '\r' || c == '\n') return false;
    for (char c : value) if (c == '\r' || c == '\n') return false;
    return true;
}
```
If a header containing embedded null characters (e.g. `Set-Cookie: session=1\0admin=true`) was passed, `isValidHeader` permitted it.
When serialized to wire or passed to underlying libraries (or C-string APIs such as `strcmp`), the string gets truncated or misparsed, enabling header injection.

### Hardening Applied
Hardened `isValidHeader` to also check for `\0`:
```cpp
for (char c : field) if (c == '\r' || c == '\n' || c == '\0') return false;
for (char c : value) if (c == '\r' || c == '\n' || c == '\0') return false;
```
The fuzz harness assertion in `fuzz_response_builder.cc` was updated to reflect that null bytes are also correctly rejected.

