#!/usr/bin/env bash
# Controlled parallel libFuzzer runner that limits CPU and memory usage.
# Usage: ./tools/run_controlled.sh [HOURS]
set -euo pipefail
HERE=$(cd "$(dirname "$0")/.." && pwd)
BIN="$HERE/out/libfuzzer"
W="$HERE/work"
HOURS=${1:-4}
SECS=$((HOURS * 3600))

# 6 high-yield targets covering all major attack surfaces
# (2 stateful VMs, 3D model, audio, text, automation)
TARGETS=(
  "fuzz_image_ops - 16384 25"
  "fuzz_model_gltf gltf.dict 1048576 25"
  "fuzz_render_vm - 16384 25"
  "fuzz_audio_wav wav.dict 262144 25"
  "fuzz_automation rae.dict 65536 10"
  "fuzz_text - 8192 10"
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

