#!/usr/bin/env bash
# Ensemble libFuzzer campaign. Splits CORES across harnesses by weight (tools/harness_table.sh),
# runs each in -fork mode (crash-resilient: a crash/oom/timeout doesn't stop the campaign), with
# entropic scheduling, value-profile on odd shards, dictionaries, and periodic corpus merge.
# Usage: tools/run_libfuzzer.sh [CORES] [HOURS] [harness-regex]       (needs ./build.sh libfuzzer)
set -euo pipefail
HERE=$(cd "$(dirname "$0")/.." && pwd); source "$HERE/tools/harness_table.sh"
CORES=${1:-$(nproc)}; HOURS=${2:-24}; FILTER=${3:-.}; BIN=$HERE/out/libfuzzer; W=$HERE/work
SECS=$((HOURS * 3600))
total=0; while read -r n d l t w; do [ -n "$n" ] && [[ $n =~ $FILTER ]] && total=$((total + w)); done <<<"$HARNESSES"
[ $total -gt 0 ] || { echo "no harness matches $FILTER"; exit 1; }
i=0
while read -r n d l t w; do
  [ -z "$n" ] || ! [[ $n =~ $FILTER ]] && continue
  j=$(( CORES * w / total )); [ $j -lt 1 ] && j=1
  mkdir -p "$W/corpus/$n" "$W/crashes/$n" "$W/logs"
  [ -d "$HERE/seeds/$n" ] && cp -n "$HERE/seeds/$n"/* "$W/corpus/$n/" 2>/dev/null || true
  args=(-fork="$j" -ignore_crashes=1 -ignore_timeouts=1 -ignore_ooms=1 -max_total_time="$SECS"
        -max_len="$l" -timeout="$t" -rss_limit_mb=3072 -malloc_limit_mb=1024 -entropic=1
        -use_value_profile=$((i % 2)) -reduce_inputs=1 -print_final_stats=1
        -artifact_prefix="$W/crashes/$n/")
  [ "$d" != "-" ] && args+=(-dict="$HERE/dict/$d")
  echo "[+] $n  jobs=$j  dict=$d"
  # FZ_UCB_STATS: each fork dumps its UCB mutation-bandit table on exit so tools/monitor.py can
  # report the winning arm and flag a collapsed bandit. (Forks share the path; last writer wins.)
  ( cd "$W/crashes/$n" && FZ_UCB_STATS="$W/logs/$n.ucb" nohup "$BIN/$n" "${args[@]}" "$W/corpus/$n" >"$W/logs/$n.log" 2>&1 & )
  i=$((i + 1))
done <<<"$HARNESSES"
echo "running; logs in $W/logs, crashes in $W/crashes. Minimise later with: tools/merge_corpora.sh"
echo "watch for plateau/saturation with: tools/monitor.py --watch 600   (writes $W/monitor.md)"
