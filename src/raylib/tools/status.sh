#!/usr/bin/env bash
HERE=$(cd "$(dirname "$0")/.." && pwd)
W="$HERE/work"

echo "=== ACTIVE PROCESSES ==="
ps -o pid,ni,%cpu,%mem,cmd -C fuzz_image_ops,fuzz_model_gltf,fuzz_render_vm,fuzz_audio_wav,fuzz_automation,fuzz_text 2>/dev/null || echo "No processes found."

echo ""
echo "=== CRASHES FOUND ==="
for d in "$W"/crashes/*; do
  if [ -d "$d" ]; then
    name=$(basename "$d")
    count=$(ls -1 "$d" 2>/dev/null | wc -l)
    echo "  $name: $count crash/timeout artifact(s)"
  fi
done

echo ""
echo "=== CORPUS SIZES ==="
for d in "$W"/corpus/*; do
  if [ -d "$d" ]; then
    name=$(basename "$d")
    count=$(ls -1 "$d" 2>/dev/null | wc -l)
    echo "  $name: $count corpus input(s)"
  fi
done

echo ""
echo "=== LATEST LOG STATS ==="
for f in "$W"/logs/*.log; do
  if [ -f "$f" ]; then
    name=$(basename "$f" .log)
    echo "--- $name ---"
    grep -E '(cov:|exec/s|peak_rss_mb|stat::number_of_executed_units)' "$f" 2>/dev/null | tail -n 5
  fi
done

