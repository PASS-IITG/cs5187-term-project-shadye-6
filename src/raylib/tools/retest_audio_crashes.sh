#!/usr/bin/env bash
set -e

CRASH_DIR=/mnt/c/Users/dxksh/Desktop/swa/raylib/work/crashes/fuzz_audio_wav
BIN=/mnt/c/Users/dxksh/Desktop/swa/raylib/out/repro/fuzz_audio_wav

export ASAN_OPTIONS="abort_on_error=1:symbolize=1"
export UBSAN_OPTIONS="print_stacktrace=1:halt_on_error=1"

echo "Running fuzz_audio_wav repro on all crash files in $CRASH_DIR..."

failed=0
count=0

for f in "$CRASH_DIR"/crash-*; do
    [ -f "$f" ] || continue
    count=$((count + 1))
    fname=$(basename "$f")
    echo -n "[$count] Testing $fname ... "
    if "$BIN" "$f" > /tmp/repro.log 2>&1; then
        echo "OK (clean exit code 0)"
    else
        exit_code=$?
        echo "FAILED (exit code $exit_code)"
        cat /tmp/repro.log
        failed=$((failed + 1))
    fi
done

echo ""
echo "Total crashes tested: $count, Failures: $failed"
if [ $failed -eq 0 ]; then
    echo "SUCCESS: All crashes resolved cleanly without ASan/UBSan errors!"
    exit 0
else
    echo "ERROR: Some crashes still failed!"
    exit 1
fi

