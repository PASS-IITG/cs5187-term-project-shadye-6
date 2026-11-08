#!/usr/bin/env bash
# Build the Drogon fuzz harnesses.  Usage: ./build.sh [libfuzzer|afl|cov|msan|repro] [DROGON_DIR]
#
# Same mode set and layout as the raylib tree. The difference is that Drogon is a large CMake project
# with external deps (trantor, jsoncpp, zlib, OpenSSL, uuid), so instead of compiling a handful of
# .c files we build Drogon + trantor ONCE as instrumented static libraries (sanitizers + libFuzzer
# coverage + our trace-pc-guard UCB channel baked in via CMAKE_CXX_FLAGS) and then link each harness
# against them. "One source, many binaries" still holds: each harness is its own libFuzzer binary
# with a per-surface corpus and dictionary.
#
#   libfuzzer : clang -fsanitize=fuzzer,address,undefined (default)
#   afl       : afl-clang-fast++ + ASan/UBSan (run again with AFL_LLVM_CMPLOG=1 for the CMPLOG twin)
#   cov       : source-based coverage (llvm-cov), standalone driver
#   msan      : MemorySanitizer (note: deps must be MSan-instrumented or expect false positives)
#   repro     : plain -O1 -g ASan/UBSan binaries with standalone main() for triage
set -euo pipefail
MODE=${1:-libfuzzer}; SRC=${2:-${DROGON_DIR:-$(dirname "$0")/../drogon}}; SRC=$(realpath "$SRC")
HERE=$(cd "$(dirname "$0")" && pwd); OUT=$HERE/out/$MODE${AFL_LLVM_CMPLOG:+-cmplog}; mkdir -p "$OUT/obj"
CC=${CC:-clang}; CXX=${CXX:-clang++}; JOBS=$(nproc)
[ -f "$SRC/lib/src/HttpRequestParser.h" ] || { echo "DROGON_DIR=$SRC does not look like the drogon source tree"; exit 1; }

BASE="-g -O1 -fno-omit-frame-pointer -gline-tables-only -w -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION"
# UB policy mirrors the raylib tree: exclude the benign-on-x86, high-frequency classes by default so
# they don't mask memory bugs; STRICT_UB=1 re-enables them for a dedicated UB campaign.
UBX="function,vptr"; [ "${STRICT_UB:-0}" = 1 ] || UBX+=",alignment,pointer-overflow,float-cast-overflow,shift-base"
SAN="-fsanitize=address,undefined -fsanitize-recover=undefined -fno-sanitize=$UBX"
UCBCOV=""                       # independent coverage channel for common/fuzz_ucb.c (see raylib tree)
case $MODE in
  libfuzzer) LIBF="-fsanitize=fuzzer-no-link"; LINKF="-fsanitize=fuzzer -Wl,--wrap=__sanitizer_cov_trace_pc_guard -Wl,--wrap=__sanitizer_cov_trace_pc_guard_init"; DRV=""; UCBCOV="-fsanitize-coverage=trace-pc-guard";;
  afl)       CC=afl-clang-fast; CXX=afl-clang-fast++; export AFL_USE_ASAN=1 AFL_USE_UBSAN=1 AFL_LLVM_LAF_ALL=${AFL_LLVM_LAF_ALL:-1}
             LIBF=""; LINKF="-fsanitize=fuzzer"; SAN="";;
  cov)       LIBF="-fprofile-instr-generate -fcoverage-mapping"; SAN=""; LINKF="$LIBF"; DRV="$HERE/common/standalone_main.c";;
  msan)      SAN="-fsanitize=memory -fsanitize-memory-track-origins=2"; LIBF="-fsanitize=fuzzer-no-link"; LINKF="-fsanitize=fuzzer -Wl,--wrap=__sanitizer_cov_trace_pc_guard -Wl,--wrap=__sanitizer_cov_trace_pc_guard_init"; UCBCOV="-fsanitize-coverage=trace-pc-guard";;
  repro)     LIBF=""; LINKF=""; DRV="$HERE/common/standalone_main.c";;
  *) echo "unknown mode $MODE"; exit 1;;
esac

# ---------- 1. Build Drogon + trantor as instrumented static libs (once per mode) ----------
DBUILD=$OUT/drogon-build
INSTRFLAGS="$BASE $SAN $LIBF $UCBCOV ${CFLAGS:-}"
if [ ! -f "$DBUILD/libdrogon.a" ] || [ "${REBUILD_DROGON:-0}" = 1 ]; then
  echo "[+] configuring Drogon ($MODE) -> $DBUILD"
  cmake -S "$SRC" -B "$DBUILD" -G "${CMAKE_GENERATOR:-Unix Makefiles}" \
    -DCMAKE_BUILD_TYPE=Debug -DBUILD_SHARED_LIBS=OFF \
    -DBUILD_ORM=OFF -DBUILD_CTL=OFF -DBUILD_EXAMPLES=OFF -DBUILD_TESTING=OFF \
    -DBUILD_YAML_CONFIG=OFF -DBUILD_BROTLI=${BUILD_BROTLI:-OFF} \
    -DCMAKE_C_COMPILER="$CC" -DCMAKE_CXX_COMPILER="$CXX" \
    -DCMAKE_C_FLAGS="$INSTRFLAGS" -DCMAKE_CXX_FLAGS="$INSTRFLAGS" >/dev/null
  echo "[+] building libdrogon.a + libtrantor.a (this is the slow part)"
  cmake --build "$DBUILD" --target drogon -j "$JOBS" >/dev/null
fi
DROGON_A=$(find "$DBUILD" -name 'libdrogon.a' | head -1)
TRANTOR_A=$(find "$DBUILD" -name 'libtrantor.a' | head -1)
[ -f "$DROGON_A" ] && [ -f "$TRANTOR_A" ] || { echo "static libs not found under $DBUILD"; exit 1; }

# include paths: public headers, PRIVATE parser headers (lib/src), trantor, generated config/exports
INC="-I$SRC/lib/inc -I$SRC/lib/src -I$SRC/trantor -I$DBUILD -I$DBUILD/exports -I$DBUILD/trantor/exports -I$HERE/common -I/usr/include/jsoncpp"
# dependency link flags (best-effort via pkg-config, with plain -l fallbacks)
dep() { pkg-config --libs "$1" 2>/dev/null || echo "${2:-}"; }
DEPS="$(dep jsoncpp -ljsoncpp) $(dep zlib -lz) -lssl -lcrypto"
command -v pkg-config >/dev/null && pkg-config --exists uuid 2>/dev/null && DEPS+=" $(pkg-config --libs uuid)" || DEPS+=" -luuid"
[ "${BUILD_BROTLI:-OFF}" = ON ] && DEPS+=" -lbrotlienc -lbrotlidec -lbrotlicommon"
# --start-group so the drogon<->trantor<->jsoncpp/ssl cross-references resolve regardless of order.
LD="-Wl,--start-group $DROGON_A $TRANTOR_A $DEPS -Wl,--end-group -lpthread -ldl -lm"

CF="$BASE $SAN $LIBF $UCBCOV $INC ${CFLAGS:-}"
CXXFLAGS_ALL="$CF -std=c++17"

# ---------- 2. shared runtime objects ----------
# fuzz_ucb.c defines the trace-pc-guard callbacks, so build it WITHOUT $UCBCOV (no self-instrument).
CF_UCB="$BASE $SAN $LIBF $INC ${CFLAGS:-}"
$CC  $CF     -c "$HERE/common/fuzz_common.c" -o "$OUT/obj/fuzz_common.o"
$CC  $CF_UCB -c "$HERE/common/fuzz_ucb.c"    -o "$OUT/obj/fuzz_ucb.o"
$CXX $CXXFLAGS_ALL -c "$HERE/common/fuzz_mock.cc" -o "$OUT/obj/fuzz_mock.o"
COMMON=("$OUT/obj/fuzz_common.o" "$OUT/obj/fuzz_ucb.o" "$OUT/obj/fuzz_mock.o")

# ---------- 3. one binary per harness ----------
EXPECT=(fuzz_http_request fuzz_http_response fuzz_multipart fuzz_multipart_form fuzz_websocket fuzz_utils fuzz_range)
link() { # name src
  local n=$1 s=$2
  $CXX $CXXFLAGS_ALL $LINKF "$HERE/harness/$s" ${DRV:-} "${COMMON[@]}" $LD -o "$OUT/$n"; }

link fuzz_http_request   fuzz_http_request.cc
link fuzz_http_response  fuzz_http_response.cc
link fuzz_multipart      fuzz_multipart.cc
link fuzz_multipart_form fuzz_multipart_form.cc
link fuzz_websocket      fuzz_websocket.cc
link fuzz_utils          fuzz_utils.cc
link fuzz_range          fuzz_range.cc

fail=0; for b in "${EXPECT[@]}"; do [ -x "$OUT/$b" ] || { echo "MISSING $b"; fail=1; }; done
cp "$HERE"/dict/*.dict "$OUT"/ 2>/dev/null || true
echo "built into $OUT"; exit $fail
