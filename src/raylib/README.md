# QTFuzz: raylib Subsystem (Phase 2 Multimedia Extension) (`src/raylib/`)

Target: `raysan5/raylib` @ `3b12ba1` (2026-11-02). 37 libFuzzer/AFL++ harnesses covering every
untrusted-input surface: 15 image decoders, 7 audio codecs, 4 font formats, 6 model formats, an
image-processing VM, a render VM over the software rasterizer, text/UTF-8, compression/encoding,
and automation-event replay.

Part of **QTFuzz** (Cross-Domain Fuzzing Through Structure-Aware Mutation and Bandit-Guided Adaptation).

---

### Verified Upstream Vulnerabilities Fixed:
- **R1:** Matrix stack underflow in `swPopMatrix()` (`rlsw.h`, CWE-119) &rarr; **Acknowledged, PR #6362 merged** (Issue [#6361](https://github.com/raysan5/raylib/issues/6361)).
- **R2:** Out-of-bounds heap read in `ExportAutomationEventList()` (`rcore.c`, CWE-125) &rarr; **Acknowledged, maintainer fixed** (Issue [#6378](https://github.com/raysan5/raylib/issues/6378)).
- **R3:** NULL-pointer dereference in `LoadWaveSamples()` (`raudio.c`, CWE-476) &rarr; **Acknowledged, maintainer fixed** in commit [7639166](https://github.com/raysan5/raylib/commit/7639166019f6d300435a2610726150558f745bee) (Issue [#6373](https://github.com/raysan5/raylib/issues/6373)).

```
./build.sh libfuzzer            # ASan+UBSan+libFuzzer  -> out/libfuzzer/
./build.sh repro                # same sanitizers, plain main()  -> triage
./build.sh afl; AFL_LLVM_CMPLOG=1 ./build.sh afl     # AFL++ (LAF-intel) + CMPLOG twin
./build.sh msan | cov           # MemorySanitizer / llvm-cov builds
STRICT_UB=1 ./build.sh libfuzzer   # + alignment, NaN->int, pointer-overflow, shift-base
python3 tools/make_seeds.py     # seeds/<harness>/  (raylib example assets + synthetic)
tools/run_libfuzzer.sh 64 48    # 64 cores, 48 h, weighted ensemble (fork mode, crash-tolerant)
tools/monitor.py --watch 600    # plateau/saturation monitor -> work/monitor.md (UCB arms too)
tools/run_afl.sh fuzz_model_gltf 15 48
tools/merge_corpora.sh; tools/coverage.sh; tools/triage.py --minimize
```
Requires clang ≥ 15 with compiler-rt (`libclang-rt-*-dev`), Python 3 (+Pillow, ffmpeg optional for seeds).

---

## 1. Attack-surface map (what reads attacker bytes)

| Module | Entry points | Parser code | Notes |
|---|---|---|---|
| rtextures | `LoadImageFromMemory`, `LoadImageAnimFromMemory` | stb_image (png bmp tga jpg gif pic psd hdr pnm), qoi.h, **rl_gputex** (dds pkm ktx pvr astc — raylib's own) | 9 of 15 decoders are *disabled by default* → least tested; build enables all |
| rtextures (ops) | ~60 `Image*` functions | raylib arithmetic: clipping, resampling, format/stride math | bugs need *sequences* of ops |
| rtext | `LoadFontData`, `LoadFontFromMemory`, `LoadFont(.fnt)`, BDF | stb_truetype, rect packer, raylib BMFont/BDF parsers | glyph-count bookkeeping |
| rmodels | `LoadModel`, `LoadModelAnimations`, `LoadMaterials` | cgltf, tinyobj, IQM, vox_loader, m3d | multi-file (gltf→bin/png, obj→mtl→png) |
| raudio | `LoadWaveFromMemory`, `LoadMusicStreamFromMemory` | dr_wav, stb_vorbis, dr_mp3, qoa, dr_flac, jar_xm, jar_mod + miniaudio converters | streaming state machines |
| rlsw (rlgl SW) | texture upload / draw | new software rasterizer | reachable from any draw call |
| rcore | `DecompressData`, `DecodeDataBase64`, path helpers, `.rae` automation | sinfl, raylib | replay indexes input arrays |

## 2. Architecture

```
            ┌──────────── seeds (example assets, PIL/ffmpeg synth, hand-built glTF/OBJ/FNT/RAE) ──┐
            ▼                                                                                     │
  libFuzzer (entropic, fork, value-profile shards) ◄──► shared corpus ◄──► AFL++ (CMPLOG main,   │
            │        ▲ custom mutators                                      MOpt, schedules)     │
            ▼        │                                                                            │
  harness ──► fz_rd param reader ──► raylib built with PLATFORM_MEMORY + GRAPHICS_API_OPENGL_SOFTWARE
     │                                  │ (headless: real InitWindow, rlsw rasterizer, null audio)
     ├─ VFS: SetLoadFile{Data,Text}Callback → in-memory multi-file container
     ├─ capped allocator: RL_MALLOC → fz_malloc (FUZZ_MAX_ALLOC_MB, NULL on excess)
     └─ oracles: round-trips / invariants → abort("FUZZ ORACLE")
            ▼
  crashes → tools/triage.py (repro build, FUZZ_KNOWN=1) → buckets(kind, top-3 frames) → known/NEW
```

Key engineering decisions:

* **Fully headless, full-fidelity build.** `PLATFORM_MEMORY` + rlsw gives a real `InitWindow()`
  with a memory framebuffer, so GPU-touching paths (texture upload of compressed formats, font
  atlases, `DrawModel` of fuzzed geometry) are fuzzed instead of stubbed. No X11/GL needed.
* **Deterministic audio.** `raudio.c` is `#include`d into the audio harness; the miniaudio device
  (null backend) is started then *stopped*, and the harness pumps the static
  `OnSendAudioDataToDevice()` mixer itself. All decoding/mixing runs on the fuzzing thread in
  input order → reproducible, no audio thread races.
* **One source, many binaries.** `fuzz_image.c` / `fuzz_audio.c` / `fuzz_font.c` / `fuzz_model.c`
  are compiled per file type (`-DFMT=".dds"`) so every binary has a pure, per-format corpus and
  dictionary instead of a selector byte that dilutes coverage feedback.
* **In-memory VFS** for formats that reference other files. Container:
  `{u8 nameLen, name, u32 len, data}*`; entry 0 is the entry point; lookups by path then basename;
  saves are swallowed (so exporters run too). Lengths are clamped, so any mutant parses.
* **Capped allocator** replaces `RL_MALLOC/CALLOC/REALLOC/FREE` via `-include`, returning NULL above
  the cap (with calloc overflow check). Header-driven 2³¹-pixel allocations become a realistic
  failure path instead of libFuzzer OOM noise.
* **Parameters without breaking seeds.** Formats that tolerate trailing data (TTF, BDF, audio)
  take harness parameters from the *last* bytes, so raw files are valid seeds; VM harnesses
  consume parameters from the front.

## 3. Strategy

**Structure-aware mutation** (`common/fuzz_common.c`)
* *Binary mutator*: 72 % libFuzzer mutate, 16 % integer-boundary injection (0, ±1, 0x7f/0x80,
  0xffff, 0x10000, 2³¹±1, 0xffffffff…; 2/4 bytes, LE or BE) into the first 512 bytes where width/
  height/count/offset fields live, 12 % block duplication (grows chunk/frame/glyph repetition).
  Then a 50 % **length-field fixup** for RIFF/WAV, MagicaVoxel, GLB and IQM so mutants pass outer
  size checks and reach inner parsers, while 50 % stay inconsistent to test those checks.
* *VFS mutator + crossover*: mutate one file inside the container (recursively with the binary
  mutator), rename (break/redirect references), duplicate/drop entries; crossover transplants whole
  files between corpus items (e.g. a glTF JSON from A with the .bin of B).
* *Dictionaries* per grammar (glTF keys/componentTypes/data-URIs, OBJ/MTL, BMFont, BDF, RIFF,
  Ogg/FLAC/ID3, tracker magics, GPU texture magics, `.rae`).
* **UCB-scheduled mutation reward** (`common/fuzz_ucb.c`). The fixed 72/16/12 split above is only the
  *fallback*. By default each mutator call treats its strategy choice as a multi-armed bandit —
  binary arms {libFuzzer, integer-edge, block-dup, mutate+fixup}; VFS arms {entry, rename, dup,
  drop, crossover} — and picks with **UCB1** (`mean + √(2·ln N / nₐ)`). The reward is *new coverage*:
  we add an independent `-fsanitize-coverage=trace-pc-guard` channel (separate from libFuzzer's own
  8-bit counters, so no symbol clash), and since exactly one produced input runs between two mutator
  calls, each call first credits the previous input's brand-new edges to the arm that made it, then
  selects the next arm. So a target whose parser only yields to, say, integer-edge injection shifts
  CPU onto that arm automatically, per-harness and online. Legal-arm sets are context-sensitive
  (drop needs >1 entry; nested entry-mutation keeps the VFS arm's credit). `FUZZ_UCB=0` restores the
  static split; `FZ_UCB_STATS=<file>` dumps the per-arm pull/reward table on exit.

**Stateful API fuzzing** (the highest-yield part)
* `fuzz_image_ops`: VM with two image registers (A target, B operand), 52 ops (resize ×3, crop,
  format to every pixel format, mipmaps, dither, rotate, colour ops, alpha ops, Gaussian blur,
  arbitrary convolution kernels, every `ImageDraw*`, palette, channel extraction, export to
  png/qoi/bmp/jpg/tga/dds). Sources: 9 generators or embedded decoded blobs.
* `fuzz_render_vm`: 48 ops over rshapes/rtext/rmodels/rlgl into rlsw: splines, rings, rounded rects,
  N-patch, 2D/3D cameras, scissor/blend/viewport state, matrix stack to overflow depth, raw
  `rlBegin` primitive streams, procedural meshes (par_shapes) + ray collision, textures uploaded in
  every pixel format with exact-size buffers.
* Value generators are edge-biased (`fz_int_edge`, `fz_float`), with *domains*: loop counts are
  clamped (`fz_count`) to avoid DoS-only hangs, coordinates to ±2¹⁶ (`fz_int_dom`), floats finite
  by default. `FUZZ_NAN=1` / `FUZZ_WIDE_INT=1` / `STRICT_UB=1` open the full domain for a
  dedicated UB campaign.

**Oracles (bugs that don't crash)**
PNG export→import pixel identity; DEFLATE and Base64 round-trip identity; UTF-8 decode→encode→decode
fixed point; `TextLength == strlen`; automation export→import count; hash determinism; header-vs-
allocation consistency (touch last byte of `GetPixelDataSize` / wave bytes); decoder must not
write to its `const` input; `IsImageValid` ⇒ sane dims. Disable with `FUZZ_NO_ORACLE=1`.

**Sanitizer policy**
ASan + UBSan (recoverable + `halt_on_error=1`, so `tools/ubsan.supp` can mute known third-party UB
while every other report still aborts). Default excludes alignment / null+0 / NaN→int /
negative-shift (benign on x86, extremely common in stb/m3d/vox/miniaudio). `-fsanitize=bounds` (in
`undefined`) is essential: it sees intra-struct array overflows ASan cannot (CORE.Input arrays).
Separate MSan build for uninitialised reads in decoders. Leak checking off in campaigns; run a leak
pass on the minimized corpus.

**Automated plateau / saturation monitor** (`tools/monitor.py`)
A long campaign silently wastes CPU once a harness stops finding coverage. The monitor samples every
`work/logs/*.log` on a cadence, keeps a rolling per-harness history of (edges, features, execs,
corpus size) in `work/monitor/state.json`, and classifies each target:
* **PROGRESSING** — edges/features still climbing inside the plateau window.
* **PLATEAU** — execs advancing but edges flat for `--plateau-min` (default 30 min): the input
  distribution is exhausted → add seeds / dict tokens / VM ops, or hand it to AFL++ CMPLOG.
* **SATURATED** — edges *and* corpus flat for `--sat-min` (default 2 h) at steady exec/s: diminishing
  returns → drop its weight in `harness_table.sh`, raise `-max_len`, or move cores elsewhere.
* **STALLED** — exec/s collapsed or log stale: crash loop / hang / OOM thrash → inspect the log.

It cross-reads each `*.ucb` dump to name the winning mutation arm and flag a bandit that has
collapsed to one arm (usually coincident with a plateau). Output is `work/monitor.md` plus a stderr
one-liner; exit status is nonzero when anything is SATURATED/STALLED. Run it by hand, from cron, or
self-looping: `tools/monitor.py --watch 600`. `run_controlled.sh` starts it automatically.

**Campaign plan** (for the other machine)
1. Day 0: `run_libfuzzer.sh` on all harnesses; CPU split by weight (raylib-authored parsers and the
   VMs get 3–6×, mature stb/dr_* get 1×). Start `tools/monitor.py --watch 600` alongside.
2. Every 6–12 h (or when the monitor flags PLATEAU/SATURATED): `merge_corpora.sh` (distil),
   `coverage.sh` (find 0 % functions → add seeds, dict tokens or VM ops), `triage.py --minimize`.
3. Plateaued targets → AFL++ (`run_afl.sh`): CMPLOG/redqueen cracks magic/checksum comparisons,
   MOpt + schedule diversity; it imports the libFuzzer corpus.
4. Fix-verify loop: once a K-bug is fixed upstream, run with `FUZZ_KNOWN=1` to regress-test.
5. Second pass with `STRICT_UB=1 FUZZ_NAN=1 FUZZ_WIDE_INT=1` and `FUZZ_API_MISUSE=1` (audio) —
   report those separately (robustness/UB class).

## 4. Findings during harness validation

All harnesses were executed **once over their seed corpora** (`-runs=0`) to validate them, plus
four 20-second sanity runs to check the mutators. No campaign was run. That alone surfaced:

| ID | Bug | Location | Repro / trigger |
|---|---|---|---|
| K1 | `GetDirectoryPath("")` reads `filePath[1]` past the terminator | rcore.c ~2578 | empty string |
| K2 | Font with none of the requested glyphs: `LoadFontData` returns 0 glyphs (calloc(0)), `GenImageFontAtlas` promotes count 0→95 and over-reads | rtext.c ~823/835 | TTF seed + absent codepoints |
| K3 | PKM loader byte-swaps its header **in the caller's `const` buffer** | rltexgpu.h ~447 | any PKM |
| K4 | rlsw `sw_pool_get`: `(int)handle >= capacity` — handles ≥ 2³¹ go negative and bypass the bound → OOB read of `gen[]` (also via `sw_pool_valid`) | rlsw.h ~1523 | `rlSetTexture(0x80000000)` |
| K5 | `PlayAutomationEvent` indexes key/mouse/touch/gamepad arrays with unchecked `.rae` params → OOB write in `CORE` (UBSan bounds) | rcore.c ~3811 | `c 1` / `e 0 1 99999 0 0 0 X` |
| K6 | `ImageTextEx` with negative spacing → width 0 → `ImageResizeNN` division by zero | rtextures.c ~1796 | spacing < 0 |
| K7 | dr_wav float→s16 conversion overflow on out-of-range float samples (UB) | dr_wav.h ~7118 | float WAV |
| K8 | raylib never calls `cgltf_validate()`: accessor/bufferView ranges beyond buffer are read OOB in `LOAD_ATTRIBUTE` | rmodels.c ~5788 | found in 20 s |
| K9 | `ImageResizeNN` "+1" ratio rounding reads one pixel past the source when new² > old·65536 (large upscales, e.g. big `ImageText` font sizes) | rtextures.c ~1795 | ImageText 256 px |
| K10 | `ImageDrawImagePro` divides by resized source width, which can be 0 (srcRec off-image or dstRec < 1 px) | rtextures.c ~4363 | VM seed |
| K11 | `ImageBlurGaussian` primes its window with `blurSize` pixels without clamping to width/height → heap over-read | rtextures.c ~2204 | blurSize ≥ width |
| K12 | Rotate/flip ops reallocate a 1-level buffer but keep `mipmaps > 1` → later `ImageCopy` overflows | rtextures.c ~2766/1209 | Mipmaps → RotateCCW → Copy |
| K13 | `FloatToHalf` shift-exponent UB for tiny/zero floats | rtextures.c ~5825 | ImageFormat → R16 |

Treat these as **unconfirmed until reproduced on your machine** (`./build.sh repro`, then run the
binary on an input with `FUZZ_KNOWN=1`). By default the harnesses *avoid* K1–K12 (guards marked
`KNOWN` in the source) and `ubsan.supp` mutes K7/K13, so campaigns spend CPU on new bugs.
`FUZZ_KNOWN=1` disables every guard.

## 5. Layout

```
build.sh                    modes: libfuzzer | afl | cov | msan | repro
common/fuzz_alloc.{h,c}     capped allocator (force-included)
common/fuzz_common.{h,c}    reader, init, VFS, UCB-scheduled mutators, oracles, known-bug switch
common/fuzz_ucb.{h,c}       UCB1 mutation-reward bandit + independent trace-pc-guard coverage channel
common/standalone_main.c    driver for repro/cov builds (files or dirs)
harness/                    fuzz_image  fuzz_image_ops  fuzz_render_vm  fuzz_font  fuzz_model
                            fuzz_audio  fuzz_text  fuzz_codec  fuzz_automation
dict/                       per-grammar dictionaries
tools/                      make_seeds.py  harness_table.sh  run_libfuzzer.sh  run_afl.sh
                            merge_corpora.sh  coverage.sh  monitor.py  triage.py  ubsan.supp
```

Env knobs: `FUZZ_LOG` (raylib logging), `FUZZ_MAX_ALLOC_MB` (256), `FUZZ_KNOWN`, `FUZZ_NO_ORACLE`,
`FUZZ_UCB` (0 disables the mutation bandit), `FZ_UCB_STATS` (per-arm table dump path),
`FUZZ_NAN`, `FUZZ_WIDE_INT`, `FUZZ_API_MISUSE`; build: `STRICT_UB`, `EXTRA_FEAT`, `CFLAGS`,
`RAYLIB_DIR` (default `../raylib`).
