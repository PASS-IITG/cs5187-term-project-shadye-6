#!/usr/bin/env python3
"""Build per-harness seed corpora in seeds/<harness>/ for the Drogon fuzzers.

Each harness has a fixed input layout (see its source); seeds are constructed to match it so they
are valid from byte 0 and the mutators start from real protocol structure:

  fuzz_http_request   : <raw HTTP request bytes><4 tail bytes = slice schedule>
  fuzz_http_response  : <raw HTTP response bytes><5 tail bytes = headMethod,closeAtEnd,schedule>
  fuzz_multipart      : <u8 ctLen><content-type><body><4 tail bytes = slice schedule>
  fuzz_multipart_form : <u8 ctLen><content-type><body>
  fuzz_websocket      : <raw WS frame bytes><3 tail bytes = isServer,schedule>
  fuzz_utils          : <mode byte><data>
  fuzz_range          : <Range header value><4 tail bytes = contentLength u32le>

Usage: tools/make_seeds.py"""
import os, struct, hashlib
HERE = os.path.dirname(os.path.abspath(__file__)); ROOT = os.path.dirname(HERE)
OUT = os.path.join(ROOT, "seeds"); MAXSZ = 1 << 20

def put(h, data, tag=""):
    if not data or len(data) > MAXSZ: return
    d = os.path.join(OUT, h); os.makedirs(d, exist_ok=True)
    open(os.path.join(d, hashlib.sha1(data).hexdigest()[:16] + tag), "wb").write(data)

SCHED = bytes([1, 3, 7, 13])          # a few slice sizes; harness clamps/repeats as needed
B = "abc"                              # default multipart boundary (matches dict + harness fallback)

# ---------- 1. HTTP requests ----------
reqs = [
    b"GET / HTTP/1.1\r\nHost: x\r\n\r\n",
    b"GET /path?a=1&b=two%20words HTTP/1.1\r\nHost: h\r\nAccept: */*\r\n\r\n",
    b"POST /f HTTP/1.1\r\nHost: h\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 7\r\n\r\na=1&b=2",
    b"POST /j HTTP/1.1\r\nHost: h\r\nContent-Type: application/json\r\nContent-Length: 13\r\n\r\n{\"k\":[1,2,3]}",
    b"POST /c HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n",
    b"PUT /x HTTP/1.1\r\nHost: h\r\nExpect: 100-continue\r\nContent-Length: 3\r\n\r\nabc",
    b"HEAD / HTTP/1.1\r\nHost: h\r\nCookie: a=b; c=d\r\nRange: bytes=0-10\r\n\r\n",
    b"OPTIONS * HTTP/1.1\r\nHost: h\r\n\r\n",
    b"GET / HTTP/1.1\r\nHost: h\r\n\r\nGET /2 HTTP/1.1\r\nHost: h\r\n\r\n",   # pipelined
]
for r in reqs: put("fuzz_http_request", r + SCHED)

# ---------- 2. HTTP responses ----------
resps = [
    b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello",
    b"HTTP/1.1 204 No Content\r\n\r\n",
    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n",
    b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}",
    b"HTTP/1.1 301 Moved\r\nLocation: /x\r\nSet-Cookie: s=1; HttpOnly\r\nContent-Length: 0\r\n\r\n",
    b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: 0\r\n\r\n",
]
for r in resps: put("fuzz_http_response", r + bytes([0, 0]) + SCHED[:3])

# ---------- 3. multipart bodies ----------
def multipart(parts):   # parts: [(name, filename|None, ctype|None, data)]
    body = b""
    for name, fn, ct, data in parts:
        body += b"--" + B.encode() + b"\r\n"
        disp = f'Content-Disposition: form-data; name="{name}"'
        if fn: disp += f'; filename="{fn}"'
        body += disp.encode() + b"\r\n"
        if ct: body += b"Content-Type: " + ct.encode() + b"\r\n"
        body += b"\r\n" + data + b"\r\n"
    body += b"--" + B.encode() + b"--\r\n"
    return body

ct = f"multipart/form-data; boundary={B}"
bodies = [
    multipart([("field", None, None, b"value")]),
    multipart([("a", None, None, b"1"), ("b", None, None, b"2")]),
    multipart([("file", "x.txt", "text/plain", b"file contents here")]),
    multipart([("f", "a.bin", "application/octet-stream", bytes(range(32)))]),
]
for b in bodies:
    seed = bytes([len(ct)]) + ct.encode() + b
    put("fuzz_multipart", seed + SCHED)
    put("fuzz_multipart_form", seed)

# ---------- 4. websocket frames ----------
def ws(fin_opcode, payload, mask=None):
    b = bytes([fin_opcode])
    n = len(payload)
    mbit = 0x80 if mask is not None else 0
    if n < 126: b += bytes([mbit | n])
    elif n < 65536: b += bytes([mbit | 126]) + struct.pack(">H", n)
    else: b += bytes([mbit | 127]) + struct.pack(">Q", n)
    if mask is not None:
        b += mask
        b += bytes(payload[i] ^ mask[i % 4] for i in range(n))
    else:
        b += payload
    return b

M = bytes([0x12, 0x34, 0x56, 0x78])
# server harness path expects masked client frames; also provide unmasked for isServer=0
for seed in [ws(0x81, b"hello", M), ws(0x82, bytes(20), M), ws(0x88, b"\x03\xe8bye", M),
             ws(0x89, b"ping", M), ws(0x81, b"frag", M)[:-1]]:
    put("fuzz_websocket", seed + bytes([1]) + SCHED[:2])     # isServer=1
for seed in [ws(0x81, b"hello"), ws(0x8a, b"pong")]:
    put("fuzz_websocket", seed + bytes([0]) + SCHED[:2])     # isServer=0

# ---------- 5. utils (mode byte + data) ----------
import base64, zlib
samples = [b"hello world", b"a=b&c=d e", b"\x00\xff\x10 raylib", "café €".encode(), b"/dir/file.txt"]
for mode in range(8):
    for s in samples:
        put("fuzz_utils", bytes([mode]) + s)
put("fuzz_utils", bytes([0]) + base64.b64encode(b"decode me"))          # hostile base64
put("fuzz_utils", bytes([1]) + b"%41%42%2f+%ff")                        # hostile url
put("fuzz_utils", bytes([2]) + zlib.compress(b"x" * 200))               # hostile gzip-ish

# ---------- 6. range strings (value + contentLength tail) ----------
for rng in [b"bytes=0-99", b"bytes=100-", b"bytes=-50", b"bytes=0-0,5-10,20-",
            b"bytes=0-99999999999999999999", b"bytes=abc", b"items=0-1"]:
    put("fuzz_range", rng + struct.pack("<I", 1000))

print("seeds:", {d: len(os.listdir(os.path.join(OUT, d))) for d in sorted(os.listdir(OUT))} if os.path.isdir(OUT) else {})
