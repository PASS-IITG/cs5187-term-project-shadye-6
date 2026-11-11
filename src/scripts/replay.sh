#!/usr/bin/env bash
set -euo pipefail

# Deterministic testcase / regression replay script
# Usage: ./scripts/replay.sh <input_file_or_dir> [target] [build_type]

INPUT_PATH="${1:-findings/known}"
TARGET="${2:-deep_fuzzer}"
BUILD_TYPE="${3:-asan}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
BIN="${ROOT_DIR}/build-${BUILD_TYPE}/${TARGET}"

if [ ! -f "${BIN}" ]; then
    "${SCRIPT_DIR}/build.sh" "${BUILD_TYPE}"
fi

export ASAN_OPTIONS="abort_on_error=1:detect_leaks=0:symbolize=1"
export UBSAN_OPTIONS="halt_on_error=1:abort_on_error=1:symbolize=1"

echo "=========================================================="
echo " Replaying inputs from: ${INPUT_PATH}"
echo " Target Binary        : ${BIN}"
echo "=========================================================="

replay_file() {
    local file="$1"
    echo -n "Replaying $(basename "${file}")... "
    set +e
    output=$("${BIN}" "${file}" 2>&1)
    status=$?
    set -e

    if [ ${status} -eq 0 ]; then
        echo "OK (Clean exit)"
    else
        echo "CRASH/SANITIZER (Exit code: ${status})"
        echo "----------------- Stack Snippet -----------------"
        echo "${output}" | grep -E "AddressSanitizer|UndefinedBehaviorSanitizer|Assertion|ABORTING" | head -n 5
        echo "-------------------------------------------------"
    fi
}

if [ -f "${INPUT_PATH}" ]; then
    replay_file "${INPUT_PATH}"
elif [ -d "${INPUT_PATH}" ]; then
    count=0
    for f in "${INPUT_PATH}"/*; do
        if [ -f "${f}" ]; then
            replay_file "${f}"
            count=$((count + 1))
        fi
    done
    echo "Replayed ${count} testcases."
else
    echo "Input path not found: ${INPUT_PATH}"
    exit 1
fi
