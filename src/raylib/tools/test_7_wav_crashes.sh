#!/usr/bin/env bash
set -e

RL=/mnt/c/Users/dxksh/Desktop/swa/raylib-src
HERE=/mnt/c/Users/dxksh/Desktop/swa/raylib

clang -g -O1 -fsanitize=address,undefined -fno-omit-frame-pointer \
    -DPLATFORM_MEMORY -DSUPPORT_TRACELOG=1 \
    -DMA_ENABLE_ONLY_SPECIFIC_BACKENDS -DMA_ENABLE_NULL \
    -DSUPPORT_FILEFORMAT_WAV=1 \
    -I$RL/src -I$HERE/tools \
    -include $HERE/tools/custom_alloc.h \
    $HERE/tools/verify_all_wav_crashes.c \
    $RL/src/raudio.c \
    -lm -lpthread -ldl \
    -o /tmp/verify_all_wav_crashes

echo "Built /tmp/verify_all_wav_crashes."

CRASHES=(
    "crash-4134b88c747d858ede9a4ee4f35868a02f734fbb"
    "crash-59769547c02c5c44b85649052df02db02f47b190"
    "crash-5ad00622a9641c577540448abb1727d514e02271"
    "crash-8fa22b77ac9077b54b9cd23d5bfd0c175d6196d9"
    "crash-cb761e3a73db28fe1edfc5ff973238e08f4e1a84"
    "crash-d071a2c33d264602e68f87f041b29d6544708915"
    "crash-f827acd8bd3ce9d7ca4173102aec6bb7df6efa95"
)

for c in "${CRASHES[@]}"; do
    echo "============================================================"
    echo "Testing $c..."
    /tmp/verify_all_wav_crashes "$HERE/work/crashes/fuzz_audio_wav/$c"
    echo ""
done

echo "ALL 7 REPRODUCERS TESTED CLEANLY WITH 0 SANITIZER VIOLATIONS!"

