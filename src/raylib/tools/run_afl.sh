#!/usr/bin/env bash
# AFL++ campaign for ONE harness: 1 main (CMPLOG/redqueen, -l 2AT transforms) + N secondaries with
# diversified power schedules, one MOpt instance and one CMPLOG-free LAF-intel instance. Shares
# the libFuzzer corpus dir as input so both engines cross-pollinate (run tools/merge_corpora.sh).
# Prereq:  ./build.sh afl  &&  AFL_LLVM_CMPLOG=1 ./build.sh afl        (AFL++ >= 4.x in PATH)
# Usage:   tools/run_afl.sh fuzz_model_gltf [N_SECONDARIES] [HOURS]
set -euo pipefail
HERE=$(cd "$(dirname "$0")/.." && pwd); source "$HERE/tools/harness_table.sh"
n=$1; N=${2:-7}; H=${3:-24}; row=$(grep -E "^$n " <<<"$HARNESSES" || true); [ -n "$row" ] || { echo "unknown $n"; exit 1; }
read -r _ d l t w <<<"$row"
B=$HERE/out/afl/$n; C=$HERE/out/afl-cmplog/$n; IN=$HERE/work/corpus/$n; OUT=$HERE/work/afl/$n
mkdir -p "$OUT"; [ -d "$IN" ] && [ "$(ls "$IN")" ] || { mkdir -p "$IN"; cp "$HERE/seeds/$n"/* "$IN/" 2>/dev/null || echo x > "$IN/x"; }
D=(); [ "$d" != "-" ] && D=(-x "$HERE/dict/$d")
export AFL_SKIP_CPUFREQ=1 AFL_TESTCACHE_SIZE=256 AFL_IMPORT_FIRST=1 AFL_FINAL_SYNC=1
common=(-i "$IN" -o "$OUT" -t $((t * 1000)) -m none -V $((H * 3600)) "${D[@]}" -G "$l")
nohup afl-fuzz -M main -c "$C" -l 2AT -p explore "${common[@]}" -- "$B" >/dev/null 2>&1 &
sched=(fast coe rare exploit explore lin quad mmopt)
for i in $(seq 1 "$N"); do
  extra=(-p "${sched[$(( (i-1) % 8 ))]}")
  [ $i -eq 1 ] && extra+=(-L 0)                    # MOpt mutator scheduling
  [ $i -eq 2 ] && extra+=(-c "$C" -l 3)            # second redqueen, aggressive transforms
  [ $((i % 3)) -eq 0 ] && export AFL_DISABLE_TRIM=1
  nohup afl-fuzz -S "s$i" "${extra[@]}" "${common[@]}" -- "$B" >/dev/null 2>&1 &
  unset AFL_DISABLE_TRIM
done
echo "AFL++ on $n: main + $N secondaries -> $OUT  (afl-whatsup $OUT)"
