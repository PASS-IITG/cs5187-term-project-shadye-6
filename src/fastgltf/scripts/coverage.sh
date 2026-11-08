#!/usr/bin/env bash
set -euo pipefail

# Script to measure and report source-based coverage using llvm-cov and llvm-profdata
# Explicitly distinguishes fastgltf coverage from simdjson/dependency coverage.
# Usage: ./scripts/coverage.sh [--corpus DIR] [--target BIN] [--out DIR]

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

CORPUS_DIR="${ROOT_DIR}/corpus/merged/initial"
TARGET="deep_fuzzer"
OUT_DIR="${ROOT_DIR}/findings/coverage_report"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --corpus) CORPUS_DIR="$2"; shift 2 ;;
        --target) TARGET="$2"; shift 2 ;;
        --out) OUT_DIR="$2"; shift 2 ;;
        *) echo "Unknown parameter: $1"; exit 1 ;;
    esac
done

BUILD_DIR="${ROOT_DIR}/build-coverage"
BIN="${BUILD_DIR}/coverage_runner"

if [ ! -f "${BIN}" ]; then
    echo "Building coverage configuration..."
    "${SCRIPT_DIR}/build.sh" coverage
fi

mkdir -p "${OUT_DIR}"
PROFRAW_DIR=$(mktemp -d /tmp/fg_profraw_XXXXXX)

echo "=========================================================="
echo " Measuring Source Coverage"
echo " Target Binary: ${BIN}"
echo " Corpus Dir   : ${CORPUS_DIR}"
echo " Report Dir   : ${OUT_DIR}"
echo "=========================================================="

export LLVM_PROFILE_FILE="${PROFRAW_DIR}/cov_%p.profraw"

# Execute all inputs in the corpus to accumulate profile counters
set +e
"${BIN}" "${CORPUS_DIR}" > /dev/null 2>&1
set -e

# Merge profiles
PROFDATA="${OUT_DIR}/coverage.profdata"
llvm-profdata merge -sparse "${PROFRAW_DIR}"/*.profraw -o "${PROFDATA}"
rm -rf "${PROFRAW_DIR}"

echo ""
echo "=== [1] fastgltf Target Coverage (Strictly Library Sources) ==="
FASTGLTF_SOURCES=(
    "${ROOT_DIR}/external/fastgltf/src"
    "${ROOT_DIR}/external/fastgltf/include"
)
llvm-cov report "${BIN}" \
    -instr-profile="${PROFDATA}" \
    "${FASTGLTF_SOURCES[@]}" | tee "${OUT_DIR}/fastgltf_coverage.txt"

echo ""
echo "=== [2] simdjson Dependency Coverage (Reported Separately) ==="
SIMDJSON_SOURCES=(
    "${ROOT_DIR}/external/fastgltf/deps/simdjson"
)
llvm-cov report "${BIN}" \
    -instr-profile="${PROFDATA}" \
    "${SIMDJSON_SOURCES[@]}" | tee "${OUT_DIR}/simdjson_coverage.txt"

# Generate HTML report
HTML_DIR="${OUT_DIR}/html"
llvm-cov show "${BIN}" \
    -instr-profile="${PROFDATA}" \
    "${FASTGLTF_SOURCES[@]}" \
    -format=html \
    -output-dir="${HTML_DIR}" 2>/dev/null || true

echo ""
echo "Source coverage report generated:"
echo "  Text summary : ${OUT_DIR}/fastgltf_coverage.txt"
echo "  HTML report  : ${HTML_DIR}/index.html"
echo "=========================================================="
