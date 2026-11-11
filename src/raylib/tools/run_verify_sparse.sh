#!/usr/bin/env bash
set -e
RL=/mnt/c/Users/dxksh/Desktop/swa/raylib-src
HERE=/mnt/c/Users/dxksh/Desktop/swa/raylib
OUT=$HERE/out/repro
CF="-g -O1 -fsanitize=address,undefined -DPLATFORM_MEMORY -DGRAPHICS_API_OPENGL_SOFTWARE -DSUPPORT_TRACELOG=1 -I$RL/src -I$HERE/common"

clang $CF $HERE/tools/verify_sparse_values.c $OUT/obj/rcore.o $OUT/obj/rshapes.o $OUT/obj/rtextures.o $OUT/obj/rtext.o $OUT/obj/rmodels.o $OUT/obj/fuzz_common.o $OUT/obj/fuzz_alloc.o -lm -lpthread -ldl -o /tmp/verify_sparse_values
/tmp/verify_sparse_values

