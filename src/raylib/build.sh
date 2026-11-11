#!/usr/bin/env bash
# Build raylib fuzz harnesses.  Usage: ./build.sh [libfuzzer|afl|cov|msan|repro] [RAYLIB_DIR]
#   libfuzzer : clang -fsanitize=fuzzer,address,undefined (default)
#   afl       : afl-clang-fast + ASan/UBSan, run again with AFL_LLVM_CMPLOG=1 for the CMPLOG twin (out/afl-cmplog)
#   cov       : source-based coverage (llvm-cov), standalone driver
#   msan      : MemorySanitizer (uninitialised reads — decoders love these)
#   repro     : plain -O1 -g ASan/UBSan binaries with standalone main() for triage
set -euo pipefail
MODE=${1:-libfuzzer}; RL=${2:-${RAYLIB_DIR:-$(dirname "$0")/../raylib}}; RL=$(realpath "$RL")
HERE=$(cd "$(dirname "$0")" && pwd); OUT=$HERE/out/$MODE${AFL_LLVM_CMPLOG:+-cmplog}; mkdir -p "$OUT/obj"
CC=${CC:-clang}; JOBS=$(nproc)

# Every disabled-by-default decoder is turned on: they are the least-tested code.
FEAT="-DPLATFORM_MEMORY -DGRAPHICS_API_OPENGL_SOFTWARE -DSUPPORT_TRACELOG=1"
for f in TGA JPG PSD HDR PIC PNM KTX ASTC PKM PVR BDF FLAC PNG BMP GIF QOI DDS TTF FNT OBJ MTL IQM GLTF VOX M3D WAV OGG MP3 QOA XM MOD; do
  FEAT+=" -DSUPPORT_FILEFORMAT_$f=1"; done
FEAT+=" ${EXTRA_FEAT:-}"        # e.g. EXTRA_FEAT=-DSUPPORT_FILEFORMAT_PEP=1
# miniaudio: null backend only -> no sound server needed, deterministic init.
AUD="-DMA_ENABLE_ONLY_SPECIFIC_BACKENDS -DMA_ENABLE_NULL"
# Route all raylib/stb/cgltf allocations through a capped allocator (see common/fuzz_alloc.h).
ALLOC="-include $HERE/common/fuzz_alloc.h"
INC="-I$RL/src -I$HERE/common"
BASE="-g -O1 -fno-omit-frame-pointer -gline-tables-only -w -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION"
# UB policy: alignment / null+0 pointer-overflow / NaN->int casts / negative<<n (fixed-point line
# stepping) are excluded by default. On x86 they
# are benign, and they're so frequent in stb/m3d/vox/miniaudio and NaN-fed draw code that they would
# mask memory bugs (NaN coords still reach the index math; ASan catches the real consequence).
# STRICT_UB=1 re-enables them for a dedicated UB-hunting campaign.
UBX="function,vptr"; [ "${STRICT_UB:-0}" = 1 ] || UBX+=",alignment,pointer-overflow,float-cast-overflow,shift-base"
# UB checks are *recoverable* so tools/ubsan.supp can mute known third-party UB; runs use
# UBSAN_OPTIONS=halt_on_error=1 so every unsuppressed report still aborts (=> a libFuzzer crash).
SAN="-fsanitize=address,undefined -fsanitize-recover=undefined -fno-sanitize=$UBX"
case $MODE in
  libfuzzer) LIBF="-fsanitize=fuzzer-no-link"; LINKF="-fsanitize=fuzzer"; DRV="";;
  afl)       CC=afl-clang-fast; export AFL_USE_ASAN=1 AFL_USE_UBSAN=1 AFL_LLVM_LAF_ALL=${AFL_LLVM_LAF_ALL:-1}
             LIBF=""; LINKF="-fsanitize=fuzzer"; SAN="";;        # afl-clang-fast provides libFuzzer-compatible main
  cov)       LIBF="-fprofile-instr-generate -fcoverage-mapping"; SAN=""; LINKF="$LIBF"; DRV="$HERE/common/standalone_main.c";;
  msan)      SAN="-fsanitize=memory -fsanitize-memory-track-origins=2"; LIBF="-fsanitize=fuzzer-no-link"; LINKF="-fsanitize=fuzzer";;
  repro)     LIBF=""; LINKF=""; DRV="$HERE/common/standalone_main.c";;
  *) echo "unknown mode $MODE"; exit 1;;
esac
# UCB mutation reward (common/fuzz_ucb.c) reads an INDEPENDENT coverage channel so it never clashes
# with libFuzzer's own 8-bit counters: our own trace-pc-guard edges. Only added where libFuzzer is
# the driver; AFL/cov/repro leave UCB reward at 0 (round-robin). FUZZ_UCB=0 disables at runtime.
UCBCOV=""; case $MODE in libfuzzer|msan) UCBCOV="-fsanitize-coverage=trace-pc-guard"; LINKF="$LINKF -Wl,--wrap=__sanitizer_cov_trace_pc_guard -Wl,--wrap=__sanitizer_cov_trace_pc_guard_init";; esac
CF="$BASE $SAN $LIBF $UCBCOV $FEAT $AUD $ALLOC $INC ${CFLAGS:-}"
# fuzz_ucb.c DEFINES the trace-pc-guard callbacks, so it must be built WITHOUT that instrumentation
# (else the guard callback is instrumented and recurses). Everything else keeps $UCBCOV.
CF_UCB="$BASE $SAN $LIBF $FEAT $AUD $ALLOC $INC ${CFLAGS:-}"

# --- 1. raylib core objects (raudio is NOT here: audio harnesses #include raudio.c for internal access) ---
LIBOBJ=()
for m in rcore rshapes rtextures rtext rmodels; do
  $CC $CF -c "$RL/src/$m.c" -o "$OUT/obj/$m.o" & LIBOBJ+=("$OUT/obj/$m.o"); done
$CC $CF -c "$HERE/common/fuzz_common.c" -o "$OUT/obj/fuzz_common.o" &
$CC $CF -c "$HERE/common/fuzz_alloc.c"  -o "$OUT/obj/fuzz_alloc.o" &
$CC $CF_UCB -c "$HERE/common/fuzz_ucb.c" -o "$OUT/obj/fuzz_ucb.o" &
wait
for o in "${LIBOBJ[@]}"; do [ -f "$o" ] || { echo "core build failed: $o"; exit 1; }; done
COMMON=("${LIBOBJ[@]}" "$OUT/obj/fuzz_common.o" "$OUT/obj/fuzz_alloc.o" "$OUT/obj/fuzz_ucb.o")
LD="-lm -lpthread -ldl"; EXPECT=()

throttle() { while [ "$(jobs -rp | wc -l)" -ge "$JOBS" ]; do wait -n || true; done; }
link() { # name src extra-defines...
  local n=$1 s=$2; shift 2; EXPECT+=("$n")
  $CC $CF $LINKF "$@" "$HERE/harness/$s" ${DRV:-} "${COMMON[@]}" $LD -o "$OUT/$n"; }

# --- 2. single-source / multi-binary families (one binary per file type => clean per-format corpora) ---
for t in png bmp tga jpg gif pic psd hdr qoi dds pkm ktx pvr astc pnm; do
  throttle; link fuzz_image_$t fuzz_image.c -DFMT=\".$t\" & done
for t in wav ogg mp3 qoa flac xm mod; do
  throttle; link fuzz_audio_$t fuzz_audio.c -DFMT=\".$t\" & done
for t in ttf otf bdf; do throttle; link fuzz_font_$t fuzz_font.c -DFMT=\".$t\" & done
wait
for t in obj iqm gltf glb vox m3d; do throttle; link fuzz_model_$t fuzz_model.c -DFMT=\".$t\" & done
link fuzz_font_fnt   fuzz_model.c -DFMT=\".fnt\" -DFNT_MODE &      # fnt = text + referenced pages => VFS
link fuzz_image_ops  fuzz_image_ops.c &
link fuzz_render_vm  fuzz_render_vm.c &
link fuzz_text       fuzz_text.c &
link fuzz_codec      fuzz_codec.c &
link fuzz_automation fuzz_automation.c &
wait
fail=0; for b in fuzz_image_{png,bmp,tga,jpg,gif,pic,psd,hdr,qoi,dds,pkm,ktx,pvr,astc,pnm} fuzz_audio_{wav,ogg,mp3,qoa,flac,xm,mod} fuzz_font_{ttf,otf,bdf,fnt} fuzz_model_{obj,iqm,gltf,glb,vox,m3d} fuzz_image_ops fuzz_render_vm fuzz_text fuzz_codec fuzz_automation; do
  [ -x "$OUT/$b" ] || { echo "MISSING $b"; fail=1; }; done
cp "$HERE"/dict/*.dict "$HERE"/options/*.options "$OUT"/ 2>/dev/null || true
echo "built into $OUT"; exit $fail
