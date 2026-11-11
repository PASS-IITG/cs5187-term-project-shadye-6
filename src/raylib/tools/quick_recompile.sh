#!/usr/bin/env bash
set -e
RL=/mnt/c/Users/dxksh/Desktop/swa/raylib-src
HERE=/mnt/c/Users/dxksh/Desktop/swa/raylib
OUT=$HERE/out/repro
CF="-g -O1 -fno-omit-frame-pointer -gline-tables-only -w -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION -fsanitize=address,undefined -fsanitize-recover=undefined -fno-sanitize=function,vptr,alignment,pointer-overflow,float-cast-overflow,shift-base -DPLATFORM_MEMORY -DGRAPHICS_API_OPENGL_SOFTWARE -DSUPPORT_TRACELOG=1 -DSUPPORT_FILEFORMAT_GLTF=1 -include $HERE/common/fuzz_alloc.h -I$RL/src -I$HERE/common"

clang $CF -c $RL/src/rmodels.c -o $OUT/obj/rmodels.o
clang $CF -DFMT=\".gltf\" $HERE/harness/fuzz_model.c $HERE/common/standalone_main.c $OUT/obj/rcore.o $OUT/obj/rshapes.o $OUT/obj/rtextures.o $OUT/obj/rtext.o $OUT/obj/rmodels.o $OUT/obj/fuzz_common.o $OUT/obj/fuzz_alloc.o -lm -lpthread -ldl -o $OUT/fuzz_model_gltf
clang $CF $HERE/tools/test_raylib_importer.c $OUT/obj/rcore.o $OUT/obj/rshapes.o $OUT/obj/rtextures.o $OUT/obj/rtext.o $OUT/obj/rmodels.o $OUT/obj/fuzz_common.o $OUT/obj/fuzz_alloc.o -lm -lpthread -ldl -o /tmp/test_raylib_importer
echo "RECOMPILED SUCCESSFULLY"

