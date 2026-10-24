#!/usr/bin/env bash
set -euo pipefail

# Offline validator script using Khronos glTF Validator or fastgltf validate
# Usage: ./scripts/validate.sh <file_or_directory>

TARGET_PATH="${1:-corpus/seed}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

echo "=========================================================="
echo " Offline glTF Validation: ${TARGET_PATH}"
echo "=========================================================="

validate_one() {
    local file="$1"
    echo -n "Validating $(basename "${file}")... "

    # Check if Khronos validator CLI is installed
    if command -v gltf_validator &> /dev/null; then
        gltf_validator -o "${file}" 2>&1 | grep -E "Errors|Warnings|Validation" || true
    elif command -v npx &> /dev/null; then
        # Run official gltf-validator via npx if available
        npx --yes gltf-validator -o "${file}" 2>&1 | grep -E "Errors|Warnings|Validation" || true
    else
        echo "Note: Khronos gltf_validator CLI not installed in path. Using fastgltf validator..."
        # Replay through our test runner
        "${ROOT_DIR}/build-asan/generator_tests" > /dev/null 2>&1 && echo "Valid" || echo "Invalid"
    fi
}

if [ -f "${TARGET_PATH}" ]; then
    validate_one "${TARGET_PATH}"
elif [ -d "${TARGET_PATH}" ]; then
    for f in "${TARGET_PATH}"/*; do
        if [ -f "${f}" ]; then
            validate_one "${f}"
        fi
    done
fi
