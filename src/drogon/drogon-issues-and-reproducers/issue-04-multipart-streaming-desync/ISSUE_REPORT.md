# Finding 04: Multipart Boundary Injection & Semantic Discrepancy between Buffered and Streaming Parsers

## Summary
- **Target Files:**
  - `drogon/lib/src/MultiPart.cc` (lines 188–200)
  - `drogon/lib/src/MultipartStreamParser.cc` (lines 62–64, 165–181)
- **Target Methods:**
  - `int drogon::MultiPartParser::parse(const HttpRequestPtr &req, const char *boundaryData, size_t boundaryLen)`
  - `void drogon::MultipartStreamParser::parse(...)`
- **Defect Class:** Grammar / Framing Discrepancy / RFC 2046 Non-conformance (Boundary Injection)
- **Severity:** Medium (Parameter Injection / WAF Bypass via malformed boundary delimiters)
- **Status:** Independently Confirmed and Discovered via `fuzz_multipart_stream` differential oracle

## Vulnerability Mechanics
RFC 2046 Section 5.1.1 governs MIME multipart body framing:
> "The boundary delimiter MUST occur at the beginning of a line, i.e., following a CRLF, and the initial CRLF is considered to be attached to the boundary delimiter line rather than part of the preceding part."
> "The boundary delimiter line is then defined as a line consisting entirely of two hyphen characters ("--") followed by the boundary parameter value..."

In `drogon/lib/src/MultipartStreamParser.cc`, Drogon's streaming parser conforms to RFC 2046:
```cpp
    dashBoundaryCrlf_ = dash_ + boundary_ + crlf_;
    crlfDashBoundary_ = crlf_ + dash_ + boundary_;
    ...
    auto pos = v.find(crlfDashBoundary_);
```
It strictly verifies that any intermediate boundary delimiter is preceded by CRLF (`\r\n`) and double hyphens (`--`).

However, in `drogon/lib/src/MultiPart.cc`, the buffered `MultiPartParser` does not enforce the RFC 2046 delimiter prefix:
```cpp
    pos2 = content.find(boundary);
    while (true)
    {
        pos1 = pos2;
        if (pos1 == std::string_view::npos)
            break;
        pos1 += boundary.length();
        ...
        pos2 = content.find(boundary, pos1);
```
`content.find(boundary)` searches for the bare boundary token anywhere in the body, without verifying that it is preceded by `\r\n--`.

## Differential Impact
When an input contains a boundary token preceded by an invalid sequence such as `\n\r` (LF-CR) or within raw field content without leading `--`:
1. `MultiPartStreamParser` (streaming) correctly rejects it as part of the body data (treating it as plain text of the preceding parameter).
2. `MultiPartParser` (buffered) splits the payload into a new form-data part, parsing injected parameter headers such as `Content-Disposition: ...; name="upload"`.

This differential behavior allows:
- **Parameter Injection:** Injecting unexpected parameters into buffered endpoints that are hidden from streaming inspectors or proxies.
- **Filter / WAF Evasion:** Inconsistencies between frontend validators (e.g. reverse proxies enforcing RFC 2046) and Drogon backend endpoints.

## Reproduction
Reproduced via differential fuzz test artifact `crash-89c3506e5641f1654dca59f9fc31f7fe8d32460b`:
- **Input Structure:**
  - Part 1 `username`: value ending with `\n\r------WebKitFormBoundary...`
  - Part 2 `upload`: parameter parsed only by buffered parser
- **Diagnostic:**
  ```
  Part count mismatch: streamedParts=1, bufferedTotal=2 (bufFiles=0, bufParams=2)
    streamed[0]: name='username', filename='', data_len=182
    bufParam: name='upload', val='Hello, Dronog multipart fuzzer!'
    bufParam: name='username', val='drogo!_user\n--'
  ```

## Defensive Remediation
In `drogon/lib/src/MultiPart.cc`, construct the exact RFC delimiter before searching:
```cpp
    std::string delimiter = "\r\n--" + std::string(boundary);
    pos2 = content.find(delimiter, pos1);
```
Ensure initial boundary searches check for `--` prefix (`"--" + boundary`) and intermediate searches check for `\r\n--` + boundary, matching the streaming parser implementation.

