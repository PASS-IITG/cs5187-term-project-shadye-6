#!/usr/bin/env bash
set -euo pipefail

# Script to merge and minimize corpus using libFuzzer -merge=1
# Usage: ./scripts/merge_corpus.sh <target_fuzzer> <dest_corpus_dir> <src_corpus_dir...>

TARGET="${1:-parser_fuzzer}"
DEST_DIR="${2:-corpus/merged/initial}"
shift 2 2>/dev/null || shift 1 2>/dev/null || true
SRC_DIRS=("$@")

if [ ${#SRC_DIRS[@]} -eq 0 ]; then
    SRC_DIRS=("corpus/seed")
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
BIN="${ROOT_DIR}/build-asan/${TARGET}"

if [ ! -f "${BIN}" ]; then
    echo "Fuzzer binary not found: ${BIN}"
    echo "Building asan target..."
    "${SCRIPT_DIR}/build.sh" asan
fi

mkdir -p "${DEST_DIR}"

echo "=========================================================="
echo " Merging corpus into: ${DEST_DIR}"
echo " Source dirs: ${SRC_DIRS[*]}"
echo " Target: ${TARGET}"
echo "=========================================================="

"${BIN}" -merge=1 "${DEST_DIR}" "${SRC_DIRS[@]}"

echo "Corpus merge completed. Unique units in ${DEST_DIR}: $(find "${DEST_DIR}" -type f | wc -l)"
