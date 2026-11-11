/* Render VM: drives rshapes + rtext + rmodels draw calls into the rlsw software rasterizer
 * (PLATFORM_MEMORY framebuffer), plus the pure-math collision/spline APIs.
 * Targets: float->int UB in clipping/segment math (NaN/Inf injected by fz_float), batch-buffer
 * overflow (rlCheckRenderBatchLimit across mode switches), rlsw triangle setup/clipping,
 * texture sampling of fuzz-uploaded textures in every pixel format, matrix-stack depth. */
#include "fuzz_common.h"
#include <stdlib.h>
#include "rlgl.h"
#include "raymath.h"

#define F(m) fz_float(&r, -(m), (m))
#define V2(m) fz_vec2(&r, m)
static Vector3 v3(fz_rd *r, float m) { Vector3 v = { fz_float(r, -m, m), fz_float(r, -m, m), fz_float(r, -m, m) }; return v; }

static Texture2D fuzz_texture(fz_rd *r) {
    int w = fz_range(r, 1, 64), h = fz_range(r, 1, 64);
    int fmt = fz_range(r, PIXELFORMAT_UNCOMPRESSED_GRAYSCALE, PIXELFORMAT_COMPRESSED_ASTC_8x8_RGBA);
    int mips = fz_range(r, 1, 7);
    long need = 0; for (int i = 0, mw = w, mh = h; i < mips; i++, mw = mw > 1 ? mw / 2 : 1, mh = mh > 1 ? mh / 2 : 1)
        need += GetPixelDataSize(mw, mh, fmt);
    unsigned char *buf = calloc(1, need > 0 ? need : 1);     /* sized exactly: OOB reads => rlsw bug */
    size_t got; const uint8_t *p = fz_bytes(r, (size_t)need, &got); memcpy(buf, p, got);
    Texture2D t = { 0 }; t.id = rlLoadTexture(buf, w, h, fmt, mips); t.width = w; t.height = h; t.format = fmt; t.mipmaps = mips;
    free(buf); return t;
}

int LLVMFuzzerTestOneInput(const uint8_t *d, size_t n) {
    fz_init(FZ_GL);
    fz_rd r = { d, n };
    Texture2D tex = fuzz_texture(&r);
    Font font = GetFontDefault();
    Material mat = LoadMaterialDefault();
    Vector2 pts[48]; int mode = 0;   /* 0 none, 1 = 2D camera, 2 = 3D camera */
    int depth = 0;

    BeginDrawing();
    ClearBackground(fz_color(&r));
    for (int step = 0; step < 64 && r.n; step++) {
        int op = fz_u8(&r) % 48;
        int c;
        switch (op) {
        case 0: DrawPixelV(V2(100), fz_color(&r)); break;
        case 1: DrawLineEx(V2(200), V2(200), F(50), fz_color(&r)); break;
        case 2: DrawLineBezier(V2(200), V2(200), F(50), fz_color(&r)); break;
        case 3: c = fz_range(&r, 0, 48); for (int i = 0; i < c; i++) pts[i] = V2(200); DrawLineStrip(pts, c, fz_color(&r)); break;
        case 4: DrawCircleSector(V2(100), F(200), F(1000), F(1000), fz_count(&r, -4, 512), fz_color(&r)); break;
        case 5: DrawRing(V2(100), F(200), F(200), F(1000), F(1000), fz_count(&r, -4, 512), fz_color(&r)); break;
        case 6: DrawEllipse(fz_int_dom(&r, -100, 100, 1 << 16), fz_int_dom(&r, -100, 100, 1 << 16), F(200), F(200), fz_color(&r)); break;
        case 7: DrawRectanglePro(fz_rect(&r, 200), V2(100), F(720), fz_color(&r)); break;
        case 8: DrawRectangleRounded(fz_rect(&r, 200), F(4), fz_count(&r, -4, 256), fz_color(&r)); break;
        case 9: DrawRectangleRoundedLinesEx(fz_rect(&r, 200), F(4), fz_count(&r, -4, 256), F(40), fz_color(&r)); break;
        case 10: c = fz_range(&r, 0, 48); for (int i = 0; i < c; i++) pts[i] = V2(200); DrawTriangleFan(pts, c, fz_color(&r)); break;
        case 11: c = fz_range(&r, 0, 48); for (int i = 0; i < c; i++) pts[i] = V2(200); DrawTriangleStrip(pts, c, fz_color(&r)); break;
        case 12: DrawPoly(V2(100), fz_count(&r, -4, 1024), F(200), F(720), fz_color(&r)); break;
        case 13: DrawPolyLinesEx(V2(100), fz_count(&r, -4, 1024), F(200), F(720), F(40), fz_color(&r)); break;
        case 14: case 15: case 16: case 17: case 18: {
            c = fz_range(&r, 0, 48); for (int i = 0; i < c; i++) pts[i] = V2(200); float th = F(30); Color col = fz_color(&r);
            if (op == 14) DrawSplineLinear(pts, c, th, col); else if (op == 15) DrawSplineBasis(pts, c, th, col);
            else if (op == 16) DrawSplineCatmullRom(pts, c, th, col); else if (op == 17) DrawSplineBezierQuadratic(pts, c, th, col);
            else DrawSplineBezierCubic(pts, c, th, col); } break;
        case 19: DrawTexturePro(tex, fz_rect(&r, 128), fz_rect(&r, 200), V2(100), F(720), fz_color(&r)); break;
        case 20: { NPatchInfo np = { fz_rect(&r, 128), fz_count(&r, -4, 128), fz_count(&r, -4, 128), fz_count(&r, -4, 128), fz_count(&r, -4, 128), fz_range(&r, 0, 3) };
                   DrawTextureNPatch(tex, np, fz_rect(&r, 200), V2(50), F(720), fz_color(&r)); } break;
        case 21: { char *s = fz_cstr(&r, 96); DrawTextPro(font, s, V2(100), V2(50), F(720), F(80), F(20), fz_color(&r)); free(s); } break;
        case 22: { int cp[16]; c = fz_range(&r, 0, 16); for (int i = 0; i < c; i++) cp[i] = fz_int_dom(&r, 0, 0x10ffff, 1 << 16);
                   DrawTextCodepoints(font, cp, c, V2(100), F(80), F(20), fz_color(&r)); (void)MeasureTextCodepoints(font, cp, c, F(80), F(20)); } break;
        case 23: BeginScissorMode(fz_int_dom(&r, -64, 64, 1 << 16), fz_int_dom(&r, -64, 64, 1 << 16), fz_int_dom(&r, -64, 128, 1 << 16), fz_int_dom(&r, -64, 128, 1 << 16)); break;
        case 24: EndScissorMode(); break;
        case 25: BeginBlendMode(fz_count(&r, -1, 16)); break;
        case 26: EndBlendMode(); break;
        case 27: if (mode) break; { Camera2D cam = { V2(100), V2(100), F(720), F(10) }; BeginMode2D(cam); mode = 1; } break;
        case 28: { Camera3D cam = { v3(&r, 50), v3(&r, 50), v3(&r, 2), F(180), fz_range(&r, 0, 1) };
                   if (mode == 1) EndMode2D(); if (mode == 2) EndMode3D(); BeginMode3D(cam); mode = 2;
                   if (fz_u8(&r) & 1) DrawBillboardPro(cam, tex, fz_rect(&r, 64), v3(&r, 20), v3(&r, 2), V2(10), V2(5), F(720), fz_color(&r)); } break;
        case 29: if (mode == 1) EndMode2D(); else if (mode == 2) EndMode3D(); mode = 0; break;
        case 30: DrawCube(v3(&r, 20), F(20), F(20), F(20), fz_color(&r)); break;
        case 31: DrawSphereEx(v3(&r, 20), F(20), fz_count(&r, -2, 128), fz_count(&r, -2, 128), fz_color(&r)); break;
        case 32: DrawCylinderEx(v3(&r, 20), v3(&r, 20), F(10), F(10), fz_count(&r, -2, 256), fz_color(&r)); break;
        case 33: DrawCapsule(v3(&r, 20), v3(&r, 20), F(10), fz_count(&r, -2, 128), fz_count(&r, -2, 128), fz_color(&r)); break;
        case 34: DrawGrid(fz_count(&r, -2, 400), F(10)); break;
        case 35: { int a = fz_count(&r, -2, 96), b = fz_count(&r, -2, 96); Mesh m;   /* procedural meshes (par_shapes) */
                   switch (fz_u8(&r) % 8) {
                   case 0: m = GenMeshPoly(a, F(10)); break;            case 1: m = GenMeshPlane(F(10), F(10), a, b); break;
                   case 2: m = GenMeshSphere(F(10), a, b); break;       case 3: m = GenMeshHemiSphere(F(10), a, b); break;
                   case 4: m = GenMeshCylinder(F(10), F(10), a); break; case 5: m = GenMeshCone(F(10), F(10), a); break;
                   case 6: m = GenMeshTorus(F(10), F(10), a, b); break; default: m = GenMeshKnot(F(10), F(10), a, b); break; }
                   if (m.vertexCount > 0) {
                       Ray ray = { v3(&r, 30), v3(&r, 1) }; (void)GetRayCollisionMesh(ray, m, MatrixIdentity());
                       (void)GetMeshBoundingBox(m); if (m.texcoords && m.normals) GenMeshTangents(&m);
                       DrawMesh(m, mat, MatrixIdentity());
                   }
                   UnloadMesh(m); } break;
        case 36: if (depth < 40) { rlPushMatrix(); depth++; } break;     /* RL_MAX_MATRIX_STACK_SIZE = 32: probe overflow guard */
        case 37: if (depth > 0) { rlPopMatrix(); depth--; } break;
        case 38: rlRotatef(F(720), F(1), F(1), F(1)); rlScalef(F(4), F(4), F(4)); rlTranslatef(F(50), F(50), F(50)); break;
        case 39: rlBegin(fz_range(&r, 0, 7)); { int k = fz_range(&r, 0, 40); for (int i = 0; i < k; i++) {
                     rlColor4ub(fz_u8(&r), fz_u8(&r), fz_u8(&r), fz_u8(&r)); rlTexCoord2f(F(2), F(2)); rlVertex3f(F(100), F(100), F(100)); } } rlEnd(); break;
        case 40: rlSetTexture(fz_u8(&r) & 1 ? tex.id : (fz_avoid_known() ? (fz_u32(&r) & 0x7fffffff) : fz_u32(&r)));   /* KNOWN: ids >= 2^31 bypass sw_pool_get bound check */ break;    /* bogus texture ids into rlsw */
        case 41: (void)CheckCollisionPointPoly(V2(100), pts, fz_range(&r, 0, 48)); break;
        case 42: { Vector2 cp; (void)CheckCollisionLines(V2(100), V2(100), V2(100), V2(100), &cp);
                   (void)CheckCollisionCircleLine(V2(100), F(50), V2(100), V2(100));
                   (void)CheckCollisionPointLine(V2(100), V2(100), V2(100), fz_count(&r, -4, 128)); (void)GetCollisionRec(fz_rect(&r, 100), fz_rect(&r, 100)); } break;
        case 43: { Ray ray = { v3(&r, 30), v3(&r, 1) }; BoundingBox bb = { v3(&r, 30), v3(&r, 30) };
                   (void)GetRayCollisionBox(ray, bb); (void)GetRayCollisionSphere(ray, v3(&r, 30), F(10));
                   (void)GetRayCollisionTriangle(ray, v3(&r, 30), v3(&r, 30), v3(&r, 30));
                   (void)GetRayCollisionQuad(ray, v3(&r, 30), v3(&r, 30), v3(&r, 30), v3(&r, 30)); } break;
        case 44: (void)GetSplinePointCatmullRom(V2(100), V2(100), V2(100), V2(100), F(2)); (void)GetSplinePointBezierCubic(V2(100), V2(100), V2(100), V2(100), F(2)); break;
        case 45: rlDrawRenderBatchActive(); break;
        case 46: { Texture2D t2 = fuzz_texture(&r); DrawTextureEx(t2, V2(64), F(720), F(4), fz_color(&r)); rlDrawRenderBatchActive(); UnloadTexture(t2); } break;
        case 47: rlViewport(fz_int_dom(&r, -64, 64, 1 << 16), fz_int_dom(&r, -64, 64, 1 << 16), fz_int_dom(&r, -64, 128, 1 << 16), fz_int_dom(&r, -64, 128, 1 << 16)); break;
        }
    }
    while (depth-- > 0) rlPopMatrix();
    if (mode == 1) EndMode2D(); else if (mode == 2) EndMode3D();
    EndScissorMode(); EndBlendMode();
    rlViewport(0, 0, 64, 48);
    EndDrawing();                       /* flush batch + rlCopyFramebuffer into memory framebuffer */
    rlSetTexture(0);
    UnloadTexture(tex);
    RL_FREE(mat.maps);                  /* default material owns only its maps array */
    return 0;
}
