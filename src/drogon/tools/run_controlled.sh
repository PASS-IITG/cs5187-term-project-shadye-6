#!/usr/bin/env bash
# Controlled parallel libFuzzer runner that limits CPU and memory usage.
# Usage: ./tools/run_controlled.sh [HOURS]
set -euo pipefail
HERE=$(cd "$(dirname "$0")/.." && pwd)
BIN="$HERE/out/libfuzzer"
W="$HERE/work"
HOURS=${1:-4}
SECS=$((HOURS * 3600))

# High-yield targets covering all major attack surfaces
# (request/response parsers, multipart, websocket framing, codec round-trips)
TARGETS=(
  "fuzz_http_request http.dict 1048576 15"
  "fuzz_http_response http.dict 1048576 15"
  "fuzz_multipart multipart.dict 1048576 15"
  "fuzz_websocket websocket.dict 262144 15"
  "fuzz_utils - 262144 10"
  "fuzz_range - 65536 10"
)

mkdir -p "$W/logs"
PIDS=()

echo "[+] Starting controlled parallel fuzzing for ${HOURS} hours (${SECS}s)..."

for entry in "${TARGETS[@]}"; do
  read -r n d l t <<< "$entry"
  mkdir -p "$W/corpus/$n" "$W/crashes/$n"
  if [ -d "$HERE/seeds/$n" ]; then
    cp -n "$HERE/seeds/$n"/* "$W/corpus/$n/" 2>/dev/null || true
  fi

  args=(
    "-fork=1"
    "-ignore_crashes=1"
    "-ignore_timeouts=1"
    "-ignore_ooms=1"
    "-max_total_time=$SECS"
    "-max_len=$l"
    "-timeout=$t"
    "-rss_limit_mb=1536"
    "-malloc_limit_mb=512"
    "-entropic=1"
    "-reduce_inputs=1"
    "-print_final_stats=1"
    "-artifact_prefix=$W/crashes/$n/"
  )
  if [ "$d" != "-" ] && [ -f "$HERE/dict/$d" ]; then
    args+=("-dict=$HERE/dict/$d")
  fi

  echo "[+] Spawning $n (nice -n 10, max_time=${SECS}s)..."
  ( cd "$W/crashes/$n" && FZ_UCB_STATS="$W/logs/$n.ucb" nice -n 10 "$BIN/$n" "${args[@]}" "$W/corpus/$n" > "$W/logs/$n.log" 2>&1 ) &
  PIDS+=($!)
done

# Background plateau/saturation monitor (writes work/monitor.md every 5 min while the run lasts).
python3 "$HERE/tools/monitor.py" --watch 300 >/dev/null 2>&1 &
MON=$!; trap 'kill $MON 2>/dev/null || true' EXIT

echo "[+] All ${#PIDS[@]} workers active. PIDs: ${PIDS[*]}"
wait "${PIDS[@]}" || true
echo "[+] All fuzzing workers finished."

