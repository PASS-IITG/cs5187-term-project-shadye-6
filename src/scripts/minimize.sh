#!/usr/bin/env bash
set -euo pipefail

# Script to minimize crash artifacts using libFuzzer -minimize_crash=1
# Usage: ./scripts/minimize.sh <crash_file> [target] [build_type]

CRASH_FILE="${1:-}"
TARGET="${2:-deep_fuzzer}"
BUILD_TYPE="${3:-asan}"

if [ -z "${CRASH_FILE}" ] || [ ! -f "${CRASH_FILE}" ]; then
    echo "Usage: $0 <path_to_crash_artifact> [target] [build_type]"
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
BIN="${ROOT_DIR}/build-${BUILD_TYPE}/${TARGET}"

MIN_DIR="${ROOT_DIR}/findings/minimized"
mkdir -p "${MIN_DIR}"

BASE_NAME=$(basename "${CRASH_FILE}")
OUT_FILE="${MIN_DIR}/minimized-${BASE_NAME}"

echo "=========================================================="
echo " Minimizing Crash Artifact: ${CRASH_FILE}"
echo " Target Binary            : ${BIN}"
echo " Output File              : ${OUT_FILE}"
echo "=========================================================="

export ASAN_OPTIONS="abort_on_error=1:symbolize=1"
export UBSAN_OPTIONS="halt_on_error=1:abort_on_error=1:symbolize=1"

set +e
"${BIN}" -minimize_crash=1 -exact_artifact_path="${OUT_FILE}" "${CRASH_FILE}"
EXIT_STATUS=$?
set -e

if [ -f "${OUT_FILE}" ]; then
    ORIG_SIZE=$(stat -c%s "${CRASH_FILE}")
    MIN_SIZE=$(stat -c%s "${OUT_FILE}")
    echo "Minimization succeeded!"
    echo "Original size : ${ORIG_SIZE} bytes"
    echo "Minimized size: ${MIN_SIZE} bytes"

    # Verify reproduction
    echo "Verifying reproducer on clean build..."
    set +e
    "${BIN}" "${OUT_FILE}" > /dev/null 2>&1
    VERIFY_STATUS=$?
    set -e
    if [ ${VERIFY_STATUS} -ne 0 ]; then
        echo "Verification confirmed: minimized artifact reliably reproduces crash (exit code ${VERIFY_STATUS})."
    else
        echo "WARNING: Minimized artifact did NOT reproduce crash!"
    fi
else
    echo "Minimization did not reduce file further or failed."
fi
