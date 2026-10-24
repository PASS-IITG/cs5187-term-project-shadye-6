#!/usr/bin/env bash
set -euo pipefail

# Build script for fastgltf fuzzing project
# Supported configurations:
#   asan         : ASan + UBSan with UBSan termination (default)
#   release-asan : ASan + UBSan with -DNDEBUG (assertions disabled)
#   coverage     : LLVM source-based code coverage (-fprofile-instr-generate)
#   integer      : Optional noisy integer sanitizers
#   all          : Builds all configurations

CONFIG="${1:-asan}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

build_config() {
    local name="$1"
    local build_dir="${ROOT_DIR}/build-${name}"
    local cmake_args=("-G" "Ninja" "-DCMAKE_CXX_COMPILER=clang++" "-DCMAKE_C_COMPILER=clang")

    echo "=========================================================="
    echo " Building configuration: ${name}"
    echo " Directory: ${build_dir}"
    echo "=========================================================="

    case "${name}" in
        asan)
            cmake_args+=(
                "-DCMAKE_BUILD_TYPE=Debug"
                "-DENABLE_ASAN=ON"
                "-DENABLE_COVERAGE=OFF"
                "-DENABLE_INTEGER_SAN=OFF"
                "-DUSE_COVERAGE_ALLOWLIST=ON"
            )
            ;;
        release-asan)
            cmake_args+=(
                "-DCMAKE_BUILD_TYPE=Release"
                "-DENABLE_ASAN=ON"
                "-DENABLE_COVERAGE=OFF"
                "-DENABLE_INTEGER_SAN=OFF"
                "-DUSE_COVERAGE_ALLOWLIST=ON"
            )
            ;;
        coverage)
            cmake_args+=(
                "-DCMAKE_BUILD_TYPE=Debug"
                "-DENABLE_ASAN=OFF"
                "-DENABLE_COVERAGE=ON"
                "-DENABLE_INTEGER_SAN=OFF"
                "-DBUILD_FUZZERS=OFF"
                "-DBUILD_UNIT_TESTS=ON"
                "-DUSE_COVERAGE_ALLOWLIST=OFF"
            )
            ;;
        integer)
            cmake_args+=(
                "-DCMAKE_BUILD_TYPE=Debug"
                "-DENABLE_ASAN=ON"
                "-DENABLE_COVERAGE=OFF"
                "-DENABLE_INTEGER_SAN=ON"
                "-DUSE_COVERAGE_ALLOWLIST=ON"
            )
            ;;
        *)
            echo "Unknown configuration: ${name}"
            exit 1
            ;;
    esac

    cmake -B "${build_dir}" -S "${ROOT_DIR}" "${cmake_args[@]}"
    ninja -C "${build_dir}"
    echo "Successfully built ${name} in ${build_dir}"
}

case "${CONFIG}" in
    all)
        build_config "asan"
        build_config "release-asan"
        build_config "coverage"
        ;;
    *)
        build_config "${CONFIG}"
        ;;
esac
