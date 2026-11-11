#!/usr/bin/env bash
set -euo pipefail

# Runner script for a single fuzzing instance
# Usage: ./scripts/fuzz.sh [options]
#   --target   : parser_fuzzer | deep_fuzzer | uri_fuzzer | base64_fuzzer (default: deep_fuzzer)
#   --mode     : byte | struct | hybrid (default: hybrid)
#   --corpus   : Corpus directory (default: corpus/work)
#   --seed_dir : Seed directory to initialize from (default: corpus/merged/initial)
#   --dict     : Dictionary file (default: corpus/gltf.dict)
#   --timeout  : Per-input timeout in seconds (default: 10)
#   --time     : Total campaign duration in seconds (default: 60)
#   --runs     : Maximum number of executions (optional)
#   --build    : asan | release-asan (default: asan)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

TARGET="deep_fuzzer"
MODE="hybrid"
BUILD_TYPE="release-asan"
CORPUS_DIR="${ROOT_DIR}/corpus/work"
SEED_DIR="${ROOT_DIR}/corpus/merged/initial"
DICT_FILE="${ROOT_DIR}/corpus/gltf.dict"
TIMEOUT=10
TIME=60
RUNS=""
EXTRA_ARGS=()

while [[ $# -gt 0 ]]; do
    case "$1" in
        --target) TARGET="$2"; shift 2 ;;
        --mode) MODE="$2"; shift 2 ;;
        --build) BUILD_TYPE="$2"; shift 2 ;;
        --corpus) CORPUS_DIR="$2"; shift 2 ;;
        --seed_dir) SEED_DIR="$2"; shift 2 ;;
        --dict) DICT_FILE="$2"; shift 2 ;;
        --timeout) TIMEOUT="$2"; shift 2 ;;
        --time) TIME="$2"; shift 2 ;;
        --runs) RUNS="$2"; shift 2 ;;
        *) EXTRA_ARGS+=("$1"); shift ;;
    esac
done

BIN="${ROOT_DIR}/build-${BUILD_TYPE}/${TARGET}"
if [ ! -f "${BIN}" ]; then
    echo "Binary not found: ${BIN}, running build..."
    "${SCRIPT_DIR}/build.sh" "${BUILD_TYPE}"
fi

mkdir -p "${CORPUS_DIR}" "${ROOT_DIR}/findings/crashes" "${ROOT_DIR}/findings/timeouts"

# Seed the working corpus if empty
if [ -d "${SEED_DIR}" ] && [ -z "$(ls -A "${CORPUS_DIR}")" ]; then
    echo "Populating ${CORPUS_DIR} with seeds from ${SEED_DIR}..."
    cp -r "${SEED_DIR}"/* "${CORPUS_DIR}/" 2>/dev/null || true
fi

export FUZZ_MODE="${MODE}"
export ASAN_OPTIONS="abort_on_error=1:detect_leaks=0:symbolize=1"
export UBSAN_OPTIONS="print_stacktrace=1:halt_on_error=1:abort_on_error=1:symbolize=1"

LIBFUZZER_FLAGS=(
    "-timeout=${TIMEOUT}"
    "-artifact_prefix=${ROOT_DIR}/findings/crashes/"
    "-len_control=0"
    "-max_len=65536"
)

if [ -f "${DICT_FILE}" ] && [[ "${TARGET}" != "uri_fuzzer" && "${TARGET}" != "base64_fuzzer" ]]; then
    LIBFUZZER_FLAGS+=("-dict=${DICT_FILE}")
fi

if [ -n "${RUNS}" ]; then
    LIBFUZZER_FLAGS+=("-runs=${RUNS}")
elif [ -n "${TIME}" ]; then
    LIBFUZZER_FLAGS+=("-max_total_time=${TIME}")
fi

echo "=========================================================="
echo " Starting Fuzzing Session"
echo " Target      : ${TARGET} (${BUILD_TYPE})"
echo " Mode        : ${MODE}"
echo " Corpus      : ${CORPUS_DIR}"
echo " Duration    : ${TIME}s (or runs: ${RUNS:-unlimited})"
echo "=========================================================="

"${BIN}" "${CORPUS_DIR}" "${LIBFUZZER_FLAGS[@]}" "${EXTRA_ARGS[@]}" || {
    EXIT_CODE=$?
    echo "Fuzz target exited with code: ${EXIT_CODE}"
    exit ${EXIT_CODE}
}
