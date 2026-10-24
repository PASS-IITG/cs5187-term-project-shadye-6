#!/usr/bin/env bash
set -euo pipefail

# Automated crash triage, deduplication, and reporting script
# Usage: ./scripts/triage.sh [crashes_dir] [target_bin]

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

CRASH_DIR="${1:-${ROOT_DIR}/findings/crashes}"
BIN="${2:-${ROOT_DIR}/build-release-asan/deep_fuzzer}"

# Fallback to build-asan if build-release-asan is not found
if [ ! -f "${BIN}" ]; then
    BIN="${ROOT_DIR}/build-asan/deep_fuzzer"
fi

exec python3 "${SCRIPT_DIR}/triage.py" "${CRASH_DIR}" "${BIN}"
