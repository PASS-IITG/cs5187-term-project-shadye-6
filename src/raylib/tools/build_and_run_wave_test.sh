#!/usr/bin/env bash
set -e

RL=/mnt/c/Users/dxksh/Desktop/swa/raylib-src
HERE=/mnt/c/Users/dxksh/Desktop/swa/raylib
OUT=$HERE/out/repro

clang -g -O1 -fsanitize=address,undefined -fno-omit-frame-pointer \
    -DPLATFORM_MEMORY -DSUPPORT_TRACELOG=1 \
    -DMA_ENABLE_ONLY_SPECIFIC_BACKENDS -DMA_ENABLE_NULL \
    -I$RL/src -I$HERE/tools \
    -include $HERE/tools/custom_alloc.h \
    $HERE/tools/test_load_wave_samples.c \
    $RL/src/raudio.c \
    -lm -lpthread -ldl \
    -o /tmp/test_load_wave_samples

echo "Built /tmp/test_load_wave_samples successfully."
