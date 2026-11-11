#!/usr/bin/env bash
# Coverage-preserving corpus distillation (libFuzzer -merge=1) for every harness in work/corpus.
set -euo pipefail
HERE=$(cd "$(dirname "$0")/.." && pwd); source "$HERE/tools/harness_table.sh"; BIN=$HERE/out/libfuzzer
for c in "$HERE"/work/corpus/*/; do
  c="${c%/}"
  n=$(basename "$c")
  [ -x "$BIN/$n" ] || continue
  mkdir -p "${c}_min"
  "$BIN/$n" -merge=1 -rss_limit_mb=3072 -timeout=30 "${c}_min" "$c" >/dev/null 2>&1 || true
  rm -rf "$c"
  mv "${c}_min" "$c"
  echo "$n: $(ls "$c" | wc -l) inputs"
done
