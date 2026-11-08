/* Model loaders over the in-memory VFS: tinyobj (OBJ+MTL), IQM, cgltf (glTF/GLB with external
 * .bin buffers + images), vox_loader, m3d — and, with -DFNT_MODE, BMFont (.fnt + page images).
 * Input is a VFS container (see fuzz_common.h); entry 0 is renamed to "main<FMT>" so every input
 * hits the intended loader, other entries are what the main file references.
 * After load we run the post-processing that consumes parsed data: skinning/animation with
 * fuzz-chosen frames (bone index arithmetic), tangent generation, bbox, OBJ export, and a real
 * software-rasterized DrawModel(). */
#include "fuzz_common.h"
#include "raymath.h"
#include "external/cgltf.h"   /* declarations only; implementation lives in rmodels.o */
#ifndef FMT
#define FMT ".gltf"
#endif
FZ_USE_VFS_MUTATOR

int LLVMFuzzerTestOneInput(const uint8_t *d, size_t n) {
    fz_init(FZ_GL);
    if (n > (8u << 20)) return 0;
    fz_file files[FZ_VFS_MAX];
    int c = fz_vfs_parse(d, n, files, FZ_VFS_MAX);
    if (!c) return 0;
    snprintf(files[0].name, sizeof files[0].name, "main%s", FMT);
    fz_vfs_mount(files, c);
    fz_rd r = { n >= 8 ? d + n - 8 : d, n >= 8 ? 8 : n };     /* animation frame params from the tail */

#ifdef FNT_MODE
    Font f = LoadFont(files[0].name);
    if (IsFontValid(f)) { Image im = ImageTextEx(f, "Hello, fnt!\n~", (float)f.baseSize, 1, WHITE); UnloadImage(im);
                          (void)MeasureTextEx(f, "Wq\xe2\x82\xac", 20, 0); }
    UnloadFont(f);
#else
    if (fz_avoid_known() && (!strcmp(FMT, ".gltf") || !strcmp(FMT, ".glb"))) {
        /* KNOWN: raylib never calls cgltf_validate(), so accessor/bufferView ranges beyond the buffer
         * are read out of bounds in LOAD_ATTRIBUTE (rmodels.c ~5788). Pre-filter those inputs. */
        cgltf_options o; memset(&o, 0, sizeof o); cgltf_data *g = NULL;
        cgltf_result res = cgltf_parse(&o, files[0].data, files[0].len, &g);
        if (res == cgltf_result_success) res = cgltf_validate(g);
        if (g) cgltf_free(g);
        if (res != cgltf_result_success) { fz_vfs_unmount(); return 0; }
    }
    Model m = LoadModel(files[0].name);
    if (IsModelValid(m)) {
        long verts = 0;
        for (int i = 0; i < m.meshCount && i < 8; i++) {
            Mesh *me = &m.meshes[i]; verts += me->vertexCount;
            (void)GetMeshBoundingBox(*me);
            if (me->vertices && me->texcoords && me->normals && me->vertexCount < 200000) GenMeshTangents(me);
            if (i == 0) ExportMesh(*me, "out.obj");               /* writer path; save callback discards */
        }
        (void)GetModelBoundingBox(m);
        int ac = 0; ModelAnimation *anims = LoadModelAnimations(files[0].name, &ac);
        for (int i = 0; anims && i < ac && i < 4; i++) {
            if (!IsModelAnimationValid(m, anims[i])) continue;
            float fr = fz_float(&r, -2, (float)anims[i].keyframeCount + 2);   /* includes NaN/Inf/negative */
            UpdateModelAnimation(m, anims[i], fr);
            UpdateModelAnimationEx(m, anims[i], fr, anims[(i + 1) % ac], fz_float(&r, -2, 64), fz_float(&r, -1, 2));
        }
        if (anims) UnloadModelAnimations(anims, ac);
        if (verts < 50000) {
            Camera3D cam = { { 3, 3, 3 }, { 0, 0, 0 }, { 0, 1, 0 }, 45, CAMERA_PERSPECTIVE };
            BeginDrawing(); BeginMode3D(cam); DrawModel(m, (Vector3){ 0 }, 1.0f, WHITE); EndMode3D(); EndDrawing();
        }
    }
    UnloadModel(m);
    int mc = 0; Material *mats = LoadMaterials(files[0].name, &mc);
    for (int i = 0; mats && i < mc; i++) UnloadMaterial(mats[i]);
    MemFree(mats);
#endif
    fz_vfs_unmount();
    return 0;
}
