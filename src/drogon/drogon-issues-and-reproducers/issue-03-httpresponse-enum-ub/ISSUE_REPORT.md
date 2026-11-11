# Finding 03: Undefined Behavior in HttpResponseParser via Unchecked Cast to Unscoped Enum HttpStatusCode

## Summary
- **Target File:** `drogon/lib/src/HttpResponseParser.cc` (line 71) & `drogon/lib/src/HttpResponseImpl.h` (line 70)
- **Target Methods:**
  - `bool HttpResponseParser::processResponseStatusLine(const char *begin, const char *end)`
  - `void HttpResponseImpl::setStatusCode(HttpStatusCode code) override`
- **Defect Class:** Undefined Behavior / Invalid Enum Value Load (`load-invalid-value`, C++17 `[dcl.enum]/8`)
- **Severity:** Medium (Crash under UBSan / Potential miscompilation / Branch elimination by optimizing compilers)
- **Status:** Independently Confirmed and Reproduced in Drogon under Clang 18.1.3 UBSan via `fuzz_http_response_raw`

## Vulnerability Mechanics
In `drogon/lib/inc/drogon/HttpTypes.h` (lines 24-106), `HttpStatusCode` is declared as an unscoped enumeration without a fixed underlying type:
```cpp
enum HttpStatusCode
{
    kUnknown = 0,
    k100Continue = 100,
    ...
    k511NetworkAuthenticationRequired = 511,
};
```
Under the ISO C++ Standard (C++17 `[dcl.enum]/8` and `[expr.static.cast]/10`):
> "For an enumeration whose underlying type is not fixed, the values are the values of an integer type with the smallest bit-field of size $b$ that can hold all enumerators..."
> "If the value of the expression is not representable by the underlying type, the behavior is undefined."

Because the highest enumerator in `HttpStatusCode` is `511` (requiring 9 to 10 bits), the valid representation range is $[0, 1023]$. Any integer outside this range cannot be held by `HttpStatusCode`.

In `drogon/lib/src/HttpResponseParser.cc`:
```cpp
    space = std::find(start, end, ' ');
    if (space != end)
    {
        std::string status_code(start, space - start);
        std::string status_message(space + 1, end - space - 1);
        LOG_TRACE << status_code << " " << status_message;
        auto code = atoi(status_code.c_str());
        responsePtr_->setStatusCode(HttpStatusCode(code));

        return true;
    }
```
`atoi()` parses an untrusted status code from the network status line (e.g., `220220` or any integer $> 1023$). It is immediately cast via `HttpStatusCode(code)` and passed into `setStatusCode(HttpStatusCode code)`.

In `HttpResponseImpl.h`:
```cpp
    void setStatusCode(HttpStatusCode code) override
    {
        statusCode_ = code;
        setStatusMessage(statusCodeToString(code));
    }
```
When `setStatusCode` is entered, the parameter `code` contains the value `220220`. Loading or accessing `code` triggers UndefinedBehaviorSanitizer:
```
drogon/lib/src/HttpResponseImpl.h:70:23: runtime error: load of value 220220, which is not a valid value for type 'HttpStatusCode'
SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior drogon/lib/src/HttpResponseImpl.h:70:23
```

## Impact & Threat Model
When Drogon is used as an HTTP client (`drogon::HttpClient`), it parses responses received from remote web servers. A malicious or malformed upstream HTTP server responding with an unexpected numeric status code (e.g. `99999` or `220220`) induces undefined behavior in the client process. Optimizing compilers (such as Clang and GCC under `-O2`/`-O3`) assume enum variables only contain valid values in the enum range; invalid loads can cause undefined control flow or dead-code elimination.

## Reproduction
Execute `fuzz_http_response_raw` with the crash artifact:
```bash
./build/asan/fuzz_http_response_raw findings/artifacts/crash-ef6e30d1adce92e688d9bc9630f196599b0f52d2
```
Output:
```
Running: findings/artifacts/crash-ef6e30d1adce92e688d9bc9630f196599b0f52d2
drogon/lib/src/HttpResponseImpl.h:70:23: runtime error: load of value 220220, which is not a valid value for type 'HttpStatusCode'
SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior drogon/lib/src/HttpResponseImpl.h:70:23
```

## Defensive Remediation
Two defensive measures should be applied upstream:

1. **Fix the enumeration underlying type** in `HttpTypes.h`:
```cpp
enum HttpStatusCode : int
{
    kUnknown = 0,
    k100Continue = 100,
    ...
};
```
Giving the enum a fixed underlying type (`: int`) defines the valid range of values as the entire range of `int` (`[-2^31, 2^31 - 1]`), making integer conversion well-defined.

2. **Validate status codes in HttpResponseParser**:
In `HttpResponseParser.cc`:
```cpp
    auto code = atoi(status_code.c_str());
    if (code < 100 || code > 999)
    {
        responsePtr_->setStatusCode(kUnknown);
    }
    else
    {
        responsePtr_->setStatusCode(static_cast<HttpStatusCode>(code));
    }
```
RFC 9110 Section 15 defines status codes as 3-digit integers (100–999). Validating before assignment conforms with RFC 9110 and prevents invalid states.

