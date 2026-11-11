# Issue 05: HTTP Request / Response Parser Malformed Header Boundary Flaw (Premature Header Termination)

## Metadata
- **Vulnerability Type:** HTTP Request Smuggling / RFC 9112 Protocol Non-Compliance / Parser Discrepancy
- **CWE:** CWE-444 (Inconsistent Interpretation of HTTP Requests / HTTP Request Smuggling)
- **Severity:** High
- **Component:** `drogon/lib/src/HttpRequestParser.cc` & `drogon/lib/src/HttpResponseParser.cc`
- **Introduced In:** Upstream commit `33f7b0eb` (Header parsing refactoring)
- **Target Functions:**
  - `HttpRequestParser::parseRequest(trantor::MsgBuffer *buf)`
  - `HttpResponseParser::parseResponse(trantor::MsgBuffer *buf)`

---

## 1. Vulnerability Mechanics

RFC 9112 Section 5.1 specifies:
> "A server MUST reject any received request message that contains an invalid header field with a response status code of 400 (Bad Request)... A recipient MUST NOT attempt to recover by guessing the sender's intent."

In upstream commit `33f7b0eb`, the header line loop in `HttpRequestParser.cc` was changed:
```cpp
auto crlf = buf->findCRLF();
while (crlf)
{
    std::string line(buf->peek(), crlf - buf->peek());
    if (!request_->addHeader(line))
    {
        // Upstream treated ANY failed line as end of headers!
        // Jumped straight to body parsing state!
        state_ = HttpRequestParseState::kGotAllHeaders;
        break;
    }
    buf->retrieveUntil(crlf + 2);
    crlf = buf->findCRLF();
}
```

### The Failure Mode
1. `addHeader(line)` returns `false` if `line.empty()` (which is the legitimate empty line `\r\n\r\n` signaling end of headers).
2. However, `addHeader(line)` **also** returns `false` if the header is malformed (e.g., missing a colon `:`, containing illegal characters, or failing name parsing).
3. Because the upstream code did not distinguish `line.empty()` from `!addHeader(line)`:
   - When a client sends a malformed line such as `InjectedHeaderNoColon\r\nTransfer-Encoding: chunked\r\n\r\n`:
   - Drogon treats `InjectedHeaderNoColon` as the **end of headers**!
   - The subsequent headers (including `Transfer-Encoding: chunked` or `Content-Length`) are then erroneously interpreted as **the start of the message body**!
4. This enables trivial **HTTP Request Smuggling** when deployed behind reverse proxies.

---

## 2. Reproduction

Sending:
```http
GET / HTTP/1.1\r\n
Host: example.com\r\n
MalformedHeaderWithoutColon\r\n
X-Secret-Header: admin\r\n\r\n
```
Expected result: Drogon immediately rejects with `400 Bad Request` (`HttpRequestParseResult::kBadMessage`).
Actual vulnerable behavior: Drogon treats `MalformedHeaderWithoutColon` as end-of-headers, leaving `X-Secret-Header` in the stream buffer.

---

## 3. Defensive Remediation

Explicitly verify that `line.empty()` is the only condition that terminates headers, and immediately return `-k400BadRequest` on non-empty malformed lines:

```diff
-    if (!request_->addHeader(line))
+    if (line.empty())
     {
+        buf->retrieveUntil(crlf + 2);
         // legitimate end of headers
+        state_ = HttpRequestParseState::kGotAllHeaders;
+        break;
     }
+    else if (!request_->addHeader(line))
+    {
+        // Malformed header line MUST be rejected with 400 Bad Request per RFC 9112
+        return HttpRequestParseResult::kBadMessage;
+    }
```

