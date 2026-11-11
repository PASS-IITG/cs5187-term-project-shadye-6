#!/usr/bin/env bash
# Source-based coverage over the current corpora -> work/cov/index.html (+ per-file text summary).
# Use it to find plateaus: functions at 0% are where to add seeds, dict tokens or harness ops.
set -euo pipefail
HERE=$(cd "$(dirname "$0")/.." && pwd); B=$HERE/out/cov; P=$HERE/work/cov; mkdir -p "$P/raw"
[ -d "$B" ] || "$HERE/build.sh" cov
for c in "$HERE"/work/corpus/*/; do n=$(basename "$c"); [ -x "$B/$n" ] || continue
  LLVM_PROFILE_FILE="$P/raw/$n-%p.profraw" timeout 1800 "$B/$n" "$c" >/dev/null 2>&1 || true; done
llvm-profdata merge -sparse "$P"/raw/*.profraw -o "$P/all.profdata"
objs=(); for b in "$B"/fuzz_*; do objs+=(-object "$b"); done
llvm-cov show "${objs[@]}" -instr-profile="$P/all.profdata" -format=html -output-dir="$P" \
  -ignore-filename-regex='raylib-fuzz/' >/dev/null
llvm-cov report "${objs[@]}" -instr-profile="$P/all.profdata" -ignore-filename-regex='raylib-fuzz/' | tee "$P/summary.txt" | tail -25
