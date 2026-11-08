# drogon-fuzz — architecture, strategy and implementation

Target: `drogonframework/drogon` @ `553b7f3` (2026-11-04). libFuzzer/AFL++ harnesses over every
remotely-reachable untrusted-input surface of the HTTP stack: the request parser, the client
response parser, buffered + streaming multipart/form-data, WebSocket frame parsing, the Range
header parser, and the codec/hash utilities (base64 / url / gzip / brotli).

This is a **port of the raylib fuzzer architecture** in `../raylib`. The mutation engine, the UCB
mutation-reward bandit, the coverage plateau/saturation monitor, the campaign tooling and the triage
pipeline are the *same code*; only the target glue (how bytes reach a parser) and the per-surface
harnesses are new. See **§6 What was kept from the raylib tree**.

```
./build.sh libfuzzer            # ASan+UBSan+libFuzzer  -> out/libfuzzer/   (builds libdrogon.a first)
./build.sh repro                # same sanitizers, plain main()  -> triage
./build.sh afl; AFL_LLVM_CMPLOG=1 ./build.sh afl     # AFL++ (LAF-intel) + CMPLOG twin
./build.sh cov | msan           # llvm-cov / MemorySanitizer builds
STRICT_UB=1 ./build.sh libfuzzer                     # + alignment, NaN->int, pointer-overflow, shift-base
python3 tools/make_seeds.py     # seeds/<harness>/  (valid requests/responses/multipart/frames)
tools/run_libfuzzer.sh 32 48    # 32 cores, 48 h, weighted ensemble (fork mode, crash-tolerant)
tools/monitor.py --watch 600    # plateau/saturation monitor -> work/monitor.md (UCB arms too)
tools/run_afl.sh fuzz_http_request 12 48
tools/merge_corpora.sh; tools/coverage.sh; tools/triage.py --minimize
```
Requires clang ≥ 15 with compiler-rt, CMake, and Drogon's build deps (jsoncpp, zlib, OpenSSL, uuid;
trantor is a submodule). Point `DROGON_DIR` at the drogon source tree (default `../drogon`).

---

## 1. Attack-surface map (what reads attacker bytes)

| Surface | Harness | Parser code | Notes |
|---|---|---|---|
| HTTP request framing | `fuzz_http_request` | `HttpRequestParser` | request line, header map, Content-Length, **chunked**, pipelining, `Expect: 100-continue`; the only surface an unauthenticated peer reaches before routing |
| HTTP response framing | `fuzz_http_response` | `HttpResponseParser` | status line, chunked, HEAD-method framing, connection-close body |
| multipart (buffered) | `fuzz_multipart_form` | `MultiPartParser` + `HttpFile` | whole-body scan, part splitting, file/param extraction, md5 |
| multipart (streaming) | `fuzz_multipart` | `MultipartStreamParser` | boundary state machine fed across slice boundaries |
| WebSocket frames | `fuzz_websocket` | `WebSocketMessageParser` | opcode/FIN/RSV, 7/16/64-bit lengths, client mask, fragmentation, control-frame rules |
| Range header | `fuzz_range` | `parseRangeHeader` | multi/suffix ranges, start/end overflow, byte-range arithmetic |
| codecs & hashes | `fuzz_utils` | `utils::` base64/url/gzip/brotli, md5/sha | hostile decode + round-trip oracles |

Query-string / form / cookie / JSON parsing is reached transitively: after `fuzz_http_request`
finishes a request it pokes the lazy post-parse parsers (`getParameters()` → query + urlencoded body,
`getJsonObject()` → jsoncpp, `getCookies()`), exactly as a real handler would.

## 2. Architecture

```
        ┌─────── seeds (valid requests/responses, multipart bodies, WS frames, codec inputs) ───────┐
        ▼                                                                                            │
  libFuzzer (entropic, fork, value-profile shards) ◄──► shared corpus ◄──► AFL++ (CMPLOG, MOpt)    │
        │   ▲ UCB-scheduled custom mutators (common/fuzz_common.c + fuzz_ucb.c, shared w/ raylib)   │
        ▼   │                                                                                        │
  harness ──► fz_rd reader ──► trantor::MsgBuffer fed in attacker-chosen SLICES ──► Drogon parser   │
        │         (headless: real trantor::EventLoop bound to this thread, MockTcpConnection)        │
        └─ oracles: base64/url/gzip round-trip identity; realContentLength==body; range in-bounds    │
        ▼                                                                                            │
  crashes → tools/triage.py (repro build) → buckets(kind, top-3 drogon/trantor frames) → known/NEW  │
        ▼                                                                                            │
  tools/monitor.py: samples logs, flags PLATEAU / SATURATED / STALLED, reads UCB arm stats ─────────┘
```

Key engineering decisions (the Drogon-specific ones; the rest is inherited):

* **Headless, real-object build.** Drogon's connection-bound parsers (`HttpRequestParser`,
  `HttpResponseParser`, `WebSocketConnectionImpl`) take a `trantor::TcpConnectionPtr` and their
  requests store an `EventLoop` and assert `isInLoopThread()`. `common/fuzz_mock.{h,cc}` provides a
  real `EventLoop` *constructed on the fuzzing thread* (so `isInLoopThread()` is true without ever
  running the loop) and a `MockTcpConnection` whose full virtual interface is stubbed (`send()`
  swallows bytes — the only I/O a parser performs, on `Expect: 100-continue`). This is the direct
  analogue of raylib's `fz_init(FZ_GL)` headless context.
* **Slice-fed state machines.** Every streaming parser is driven exactly like the server/client:
  bytes are appended to a `MsgBuffer` in **edge-biased slices** and the parser is pumped after each
  append, so header/body/chunk/frame boundaries land mid-token. This makes the bug class *sequences
  of partial feeds* — the HTTP counterpart of raylib's stateful image/render VMs, which also needed
  a specific sequence of states rather than one blob.
* **Library, not source, compilation.** Drogon is a CMake project with heavy deps, so `build.sh`
  builds `libdrogon.a` + `libtrantor.a` **once per mode** with the sanitizer + libFuzzer coverage +
  UCB `trace-pc-guard` flags injected via `CMAKE_CXX_FLAGS`, then links each harness against them.
  "One source, many binaries" still holds — each harness is its own libFuzzer binary with a pure
  per-surface corpus and dictionary. (Raylib compiled 5 `.c` files directly; the only reason this
  differs is Drogon's size.)
* **Parameters without breaking seeds.** Formats that tolerate trailing data (raw HTTP requests,
  responses, WS frames) take harness parameters — the slice schedule, head-method / is-server flags
  — from the *last* bytes, so a raw `.http`/frame file is a valid seed, exactly as the raylib tree
  took TTF/audio parameters from the tail.

## 3. Strategy

**Structure-aware mutation** (`common/fuzz_common.c` — the same engine as the raylib tree)
* *Binary mutator*: libFuzzer mutate + integer-boundary injection into the header region + block
  duplication (grows repeated headers / chunks / parts), then a probabilistic **framing fixup**:
  retargeted from raylib's RIFF/GLB/IQM length fields to HTTP **Content-Length** (rewritten
  in place, length-preserving, to match the actual body), so half the mutants pass framing checks
  and reach deep parser states while half stay inconsistent to test request-smuggling / truncation
  paths.
* *Container mutator + crossover* (`fz_mutate_vfs`): the generic length-prefixed container is reused
  for multi-part inputs the way raylib used it for gltf+bin+png.
* *Dictionaries* per grammar: `http.dict` (methods, versions, headers, `chunked`, `100-continue`),
  `multipart.dict` (boundary / Content-Disposition), `websocket.dict` (opcode + length bytes).

**UCB-scheduled mutation reward** (`common/fuzz_ucb.{h,c}` — shared byte-for-byte with the raylib
tree). Each mutator call picks its strategy with **UCB1**; the reward is new coverage, measured on an
independent `-fsanitize-coverage=trace-pc-guard` channel so it never clashes with libFuzzer's own
8-bit counters. A surface whose parser only yields to, say, integer-edge injection (chunk lengths,
WS extended lengths) shifts CPU onto that arm automatically. `FUZZ_UCB=0` restores the static split;
`FZ_UCB_STATS=<file>` dumps the per-arm table.

**Oracles (bugs that don't crash)** — `FUZZ_NO_ORACLE=1` to disable:
* `base64Decode(base64Encode(x)) == x`, `urlDecode(urlEncode(x)) == x`,
  `gzipDecompress(gzipCompress(x)) == x`, `brotli…` round-trip (when built).
* `HttpRequest::realContentLength() == body bytes` for in-memory bodies.
* every range returned by `parseRangeHeader` satisfies `start < end <= contentLength` (half-open).
* `getMd5` determinism.

**Automated plateau / saturation monitor** (`tools/monitor.py` — identical to the raylib tree).
Samples `work/logs/*.log`, keeps rolling per-harness history, and classifies each target
PROGRESSING / PLATEAU / SATURATED / STALLED with a recommendation, cross-reading each `*.ucb` dump
to name the winning mutation arm and flag a collapsed bandit. `tools/run_controlled.sh` starts it
automatically; otherwise `tools/monitor.py --watch 600`.

**Sanitizer policy.** ASan + UBSan (recoverable + `halt_on_error=1`, so `tools/ubsan.supp` can mute
known benign third-party UB while every other report aborts). Default excludes alignment / null+0 /
NaN→int / negative-shift (benign on x86, frequent in deps). `-fsanitize=bounds` catches intra-struct
array overflows ASan cannot. A separate MSan build finds uninitialised reads (note: for clean MSan
the deps must also be MSan-instrumented, else expect false positives from libssl/zlib).

**Campaign plan**
1. Day 0: `run_libfuzzer.sh` on all harnesses; CPU split by weight (`fuzz_http_request` and the
   multipart parsers get 4–6×). Start `tools/monitor.py --watch 600`.
2. On a monitor PLATEAU/SATURATED flag (or every 6–12 h): `merge_corpora.sh`, `coverage.sh`
   (0 % functions → add seeds / dict tokens), `triage.py --minimize`.
3. Plateaued targets → AFL++ (`run_afl.sh`): CMPLOG cracks the magic/length/boundary comparisons
   (chunk-size hex, WS length prefixes, multipart boundary match).
4. Enable the extra surfaces for a second pass: `enableCompressedRequest` / `enableRequestStream`
   are off by default in the mock app; a campaign that flips them (via a small harness edit) reaches
   `decompressBody()` and the stream-reader path.

## 4. Findings

None catalogued yet — the harnesses are provided validated against their seed corpora but no campaign
has been run here. As bugs are confirmed, add a signature to `KNOWN` in `tools/triage.py` (so later
campaigns don't re-triage them) and a row to this table.

## 5. Layout

```
build.sh                    builds libdrogon.a/libtrantor.a (instrumented) then links harnesses
common/fuzz_mock.{h,cc}     headless EventLoop + MockTcpConnection (Drogon analogue of fz_init GL)
common/fuzz_common.{h,c}    reader, container, UCB-scheduled mutators, HTTP framing fixup, oracles
common/fuzz_ucb.{h,c}       UCB1 mutation-reward bandit + trace-pc-guard channel (shared w/ raylib)
common/standalone_main.c    driver for repro/cov builds
harness/                    fuzz_http_request  fuzz_http_response  fuzz_multipart
                            fuzz_multipart_form  fuzz_websocket  fuzz_utils  fuzz_range
dict/                       http  multipart  websocket
tools/                      make_seeds.py  harness_table.sh  run_libfuzzer.sh  run_afl.sh
                            run_controlled.sh  merge_corpora.sh  coverage.sh  monitor.py
                            triage.py  status.sh  ubsan.supp
```

Env knobs: `FUZZ_LOG` (trantor logging), `FUZZ_KNOWN`, `FUZZ_NO_ORACLE`, `FUZZ_UCB` (0 disables the
mutation bandit), `FZ_UCB_STATS` (per-arm dump path); build: `STRICT_UB`, `BUILD_BROTLI`,
`REBUILD_DROGON=1` (force a fresh libdrogon build), `CFLAGS`, `DROGON_DIR`.

## 6. What was kept from the raylib tree

Unchanged (same files, copied or near-identical):
* `common/fuzz_ucb.{h,c}` — the UCB1 bandit + coverage-reward channel, **byte-for-byte**.
* `tools/monitor.py` — the plateau/saturation monitor, **byte-for-byte**.
* `tools/run_libfuzzer.sh`, `run_afl.sh`, `run_controlled.sh`, `merge_corpora.sh`, `status.sh` —
  generic (they iterate `harness_table.sh` / the `work/` dirs), copied verbatim.
* `common/fuzz_common.{h,c}` — the FuzzedDataProvider-lite reader, the length-prefixed container,
  the UCB-scheduled binary/container mutators and the oracle macro are the **same engine**; only the
  raylib-typed helpers and the file-callback VFS mount were dropped and `fz_fixup` was retargeted to
  HTTP Content-Length.
* `common/standalone_main.c`, `tools/coverage.sh`, `tools/triage.py` — same drivers; only paths and
  the triage frame-filter / KNOWN table are Drogon-specific.
* The whole build-mode set (`libfuzzer|afl|cov|msan|repro`), the UB policy, the sanitizer options and
  the tail-parameter seed convention are identical.

New (Drogon-specific): `common/fuzz_mock.{h,cc}` (headless connection), the seven `harness/*.cc`,
the three dicts, `harness_table.sh` weights, and `make_seeds.py`. The only structural difference is
that `build.sh` builds Drogon as a static library via CMake (because it is a large multi-dependency
project) instead of compiling a few `.c` files directly.
