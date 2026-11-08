# Issue 06: Differential Request Framing Discrepancy between Drogon and llhttp on Non-ASCII Octets

## Metadata
- **Vulnerability Type:** Differential Protocol Interpretation / Request Framing Discrepancy
- **CWE:** CWE-444 (Inconsistent Interpretation of HTTP Requests)
- **Severity:** Medium
- **Component:** `HttpRequestParser.cc` vs Node.js / `llhttp`
- **Reproducer Artifact:** `crash-7b730c93c3038fb2626e5da85bd59aa44a24c85f` (3 bytes: `\r\n\xfa`)

---

## 1. Mechanics

RFC 9112 Section 2.2 defines the request line:
> "A recipient that receives whitespace between the start-line and the first header field MUST reject the message with a 400 (Bad Request) status code..."
> Section 2.1: "In the interest of robustness, a recipient that is expecting to receive and parse a request-line SHOULD ignore at least one empty line (CRLF) received prior to any request-line."

When parsing `\r\n\xfa`:
1. **llhttp (Node.js engine):**
   - Strips the leading CRLF.
   - Observes `0xfa` (an invalid non-ASCII character for HTTP method token).
   - Immediately returns an unrecoverable parse error (`outcome=2: kError`).
2. **Drogon:**
   - Strips the leading CRLF.
   - Observes `0xfa`, but does not observe a trailing space or delimiter to complete the method string.
   - Returns `outcome=0: kIncomplete`, leaving the socket open and waiting for more characters.

### Impact
When Drogon is deployed behind a reverse proxy that parses with `llhttp` or strict token validation, this discrepancy enables HTTP desynchronization. If a frontend forwards or buffers the initial octets, Drogon keeps the connection state alive in a half-parsed state, which can be combined with subsequent pipelined requests.

