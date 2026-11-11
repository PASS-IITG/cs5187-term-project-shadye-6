#!/usr/bin/env bash
set -e

RL=/mnt/c/Users/dxksh/Desktop/swa/raylib-src
HERE=/mnt/c/Users/dxksh/Desktop/swa/raylib
OUT=$HERE/out/repro

clang -g -O1 -fsanitize=address,undefined -fno-omit-frame-pointer \
    -DPLATFORM_MEMORY -DGRAPHICS_API_OPENGL_SOFTWARE -DSUPPORT_TRACELOG=1 \
    -I$RL/src -I$HERE/common \
    -include $HERE/common/fuzz_alloc.h \
    $HERE/tools/test_export_automation.c \
    $RL/src/rcore.c \
    $OUT/obj/rshapes.o \
    $OUT/obj/rtextures.o \
    $OUT/obj/rtext.o \
    $OUT/obj/rmodels.o \
    $OUT/obj/fuzz_common.o \
    $OUT/obj/fuzz_alloc.o \
    -lm -lpthread -ldl \
    -o /tmp/test_export_automation

echo "Built /tmp/test_export_automation successfully."
