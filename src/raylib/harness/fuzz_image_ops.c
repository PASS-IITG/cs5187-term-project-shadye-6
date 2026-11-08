/* Stateful image-processing VM. Input = [source selector][params...][op stream].
 * Two image registers (A = target, B = operand) let ops compose: ImageDraw(A,B), AlphaMask(A,B),
 * format conversion followed by crop/rotate/resize, mipmap chains followed by format change, etc.
 * The bugs here are arithmetic (rect clipping, negative sizes, stride math across formats), which
 * single-call fuzzing never reaches because it needs a specific *sequence* of states. */
#include "fuzz_common.h"
#include <stdlib.h>

/* KNOWN (K9): ImageResizeNN's "+1" ratio rounding reads one pixel past the source when
 * new^2 > old*65536 (large upscales) — rtextures.c ~1795. */
static int nn_known(Image a, int w, int h) {
    return (long long)w * w > (long long)a.width * 65536 || (long long)h * h > (long long)a.height * 65536; }
/* KNOWN (K10): ImageDrawImagePro divides by the (resized) source width; a srcRec outside the
 * source or a dstRec that truncates to 0 px yields width 0 => SIGFPE (rtextures.c ~4363). */
static int src_ok(Image b, Rectangle q) {
    return q.x >= 0 && q.y >= 0 && q.width >= 1 && q.height >= 1 && q.x + q.width <= b.width && q.y + q.height <= b.height; }
static int px_ok(int w, int h) { return w <= 0 || h <= 0 || (long long)w * h <= FZ_PIXEL_CAP; }

static Image make_source(fz_rd *r) {
    int w = fz_int_dom(r, 0, 300, 1 << 16), h = fz_int_dom(r, 0, 300, 1 << 16);
    if (!px_ok(w, h) || w > 4096 || h > 4096) { w = 17; h = 13; }
    switch (fz_u8(r) % 11) {
    case 0: return GenImageColor(w, h, fz_color(r));
    case 1: return GenImageGradientLinear(w, h, fz_int_dom(r, 0, 360, 1 << 16), fz_color(r), fz_color(r));
    case 2: return GenImageGradientRadial(w, h, fz_float(r, -2, 2), fz_color(r), fz_color(r));
    case 3: return GenImageGradientSquare(w, h, fz_float(r, -2, 2), fz_color(r), fz_color(r));
    case 4: return GenImageChecked(w, h, fz_int_dom(r, 0, 64, 1 << 16), fz_int_dom(r, 0, 64, 1 << 16), fz_color(r), fz_color(r));
    case 5: return GenImageWhiteNoise(w, h, fz_float(r, -1, 2));
    case 6: return GenImagePerlinNoise(w, h, fz_int_dom(r, -1000, 1000, 1 << 16), fz_int_dom(r, -1000, 1000, 1 << 16), fz_float(r, -10, 10));
    case 7: return GenImageCellular(w, h, fz_int_dom(r, 0, 64, 1 << 16));
    case 8: { char *s = fz_cstr(r, 64); Image i = GenImageText(w, h, s); free(s); return i; }
    case 9: { char *s = fz_cstr(r, 32); Image i = ImageText(s, fz_count(r, -2, fz_avoid_known() ? 64 : 256), fz_color(r)); free(s); return i; }
    default: {   /* embedded QOI/PNG/BMP blob (u16 length) for real-world pixel layouts */
        static const char *ft[] = { ".qoi", ".png", ".bmp", ".gif" };
        const char *t = ft[fz_u8(r) & 3]; size_t got; const uint8_t *b = fz_bytes(r, fz_u16(r), &got);
        Image i = LoadImageFromMemory(t, b, (int)got);
        return IsImageValid(i) ? i : GenImageColor(w, h, fz_color(r));
    }
    }
}

static int read_points(fz_rd *r, Vector2 *pts, int max) {
    int c = fz_range(r, 0, max); for (int i = 0; i < c; i++) pts[i] = fz_vec2(r, 400); return c;
}

int LLVMFuzzerTestOneInput(const uint8_t *d, size_t n) {
    fz_init(FZ_GL);   /* default font (ImageText/ImageDrawText) needs InitWindow */
    fz_rd r = { d, n };
    Image A = make_source(&r), B = make_source(&r);
    Vector2 pts[32]; float kernel[49];

    for (int step = 0; step < 48 && r.n; step++) {
        if (!IsImageValid(A)) { UnloadImage(A); A = GenImageColor(8, 8, RED); }
        int op = fz_u8(&r);
        switch (op % 52) {
        case 0: { int w = fz_int_dom(&r, -4, 512, 1 << 16), h = fz_int_dom(&r, -4, 512, 1 << 16); if (px_ok(w, h)) ImageResize(&A, w, h); } break;
        case 1: { int w = fz_int_dom(&r, -4, 512, 1 << 16), h = fz_int_dom(&r, -4, 512, 1 << 16); if (px_ok(w, h) && !(fz_avoid_known() && nn_known(A, w, h))) ImageResizeNN(&A, w, h); } break;
        case 2: { int w = fz_int_dom(&r, -4, 512, 1 << 16), h = fz_int_dom(&r, -4, 512, 1 << 16); if (px_ok(w, h))
                  ImageResizeCanvas(&A, w, h, fz_int_dom(&r, -600, 600, 1 << 16), fz_int_dom(&r, -600, 600, 1 << 16), fz_color(&r)); } break;
        case 3: ImageCrop(&A, fz_rect(&r, 600)); break;
        case 4: ImageFormat(&A, fz_int_dom(&r, 0, PIXELFORMAT_COMPRESSED_ASTC_8x8_RGBA + 1, 1 << 16)); break;
        case 5: if (!fz_avoid_known()) ImageMipmaps(&A); break;   /* KNOWN (K12): Rotate/Flip keep mipmaps>1 on a 1-level buffer => ImageCopy overflow */
        case 6: ImageDither(&A, fz_int_dom(&r, 0, 9, 1 << 16), fz_int_dom(&r, 0, 9, 1 << 16), fz_int_dom(&r, 0, 9, 1 << 16), fz_int_dom(&r, 0, 9, 1 << 16)); break;
        case 7: ImageFlipVertical(&A); break;
        case 8: ImageFlipHorizontal(&A); break;
        case 9: ImageRotate(&A, fz_int_dom(&r, -720, 720, 1 << 16)); break;
        case 10: ImageRotateCW(&A); break;
        case 11: ImageRotateCCW(&A); break;
        case 12: ImageColorTint(&A, fz_color(&r)); break;
        case 13: ImageColorInvert(&A); break;
        case 14: ImageColorGrayscale(&A); break;
        case 15: ImageColorContrast(&A, fz_int_dom(&r, -200, 200, 1 << 16)); break;
        case 16: ImageColorBrightness(&A, fz_int_dom(&r, -300, 300, 1 << 16)); break;
        case 17: ImageColorReplace(&A, fz_color(&r), fz_color(&r)); break;
        case 18: ImageAlphaCrop(&A, fz_float(&r, -1, 2)); break;
        case 19: ImageAlphaClear(&A, fz_color(&r), fz_float(&r, -1, 2)); break;
        case 20: ImageAlphaMask(&A, B); break;
        case 21: ImageAlphaPremultiply(&A); break;
        case 22: { int bs = fz_count(&r, -2, 32);   /* KNOWN (K11): window primed with blurSize px, unclamped to width/height */
                   if (!fz_avoid_known() || (bs < A.width && bs < A.height)) ImageBlurGaussian(&A, bs); } break;
        case 23: { int k = fz_range(&r, 0, 7); for (int i = 0; i < k * k; i++) kernel[i] = fz_float(&r, -4, 4);
                   ImageKernelConvolution(&A, kernel, k * k); } break;
        case 24: { int k = fz_int_dom(&r, 0, 49, 1 << 16); if (k >= 0 && k <= 49) { for (int i = 0; i < k; i++) kernel[i] = fz_float(&r, -4, 4);
                   ImageKernelConvolution(&A, kernel, k); } } break;
        case 25: ImageToPOT(&A, fz_color(&r)); break;
        case 26: { Image t = ImageFromImage(A, fz_rect(&r, 600)); UnloadImage(B); B = t; } break;
        case 27: { Image t = ImageFromChannel(A, fz_int_dom(&r, -1, 4, 1 << 16)); UnloadImage(B); B = t; } break;
        case 28: { Image t = ImageCopy(A); UnloadImage(B); B = t; } break;
        case 29: { Image t = A; A = B; B = t; } break;
        case 30: { int c = 0; Color *p = LoadImagePalette(A, fz_int_dom(&r, -1, 300, 1 << 16), &c); UnloadImagePalette(p); } break;
        case 31: (void)GetImageAlphaBorder(A, fz_float(&r, -1, 2)); break;
        case 32: (void)GetImageColor(A, fz_int_dom(&r, -2, 600, 1 << 16), fz_int_dom(&r, -2, 600, 1 << 16)); break;
        case 33: ImageClearBackground(&A, fz_color(&r)); break;
        case 34: ImageDrawPixelV(&A, fz_vec2(&r, 600), fz_color(&r)); break;
        case 35: ImageDrawLineEx(&A, fz_vec2(&r, 600), fz_vec2(&r, 600), fz_count(&r, -4, 256), fz_color(&r)); break;
        case 36: { int c = read_points(&r, pts, 32); ImageDrawLineStrip(&A, pts, c, fz_color(&r)); } break;
        case 37: ImageDrawTriangle(&A, fz_vec2(&r, 600), fz_vec2(&r, 600), fz_vec2(&r, 600), fz_color(&r)); break;
        case 38: ImageDrawTriangleGradient(&A, fz_vec2(&r, 600), fz_vec2(&r, 600), fz_vec2(&r, 600), fz_color(&r), fz_color(&r), fz_color(&r)); break;
        case 39: { int c = read_points(&r, pts, 32); ImageDrawTriangleFan(&A, pts, c, fz_color(&r)); } break;
        case 40: { int c = read_points(&r, pts, 32); ImageDrawTriangleStrip(&A, pts, c, fz_color(&r)); } break;
        case 41: ImageDrawRectanglePro(&A, fz_rect(&r, 600), fz_vec2(&r, 600), fz_float(&r, -720, 720), fz_color(&r)); break;
        case 42: ImageDrawRectangleLinesEx(&A, fz_rect(&r, 600), fz_count(&r, -4, 256), fz_color(&r)); break;
        case 43: ImageDrawRectangleGradientEx(&A, fz_rect(&r, 600), fz_color(&r), fz_color(&r), fz_color(&r), fz_color(&r)); break;
        case 44: ImageDrawCircleV(&A, fz_vec2(&r, 600), fz_count(&r, -4, 2048), fz_color(&r)); break;
        case 45: ImageDrawCircleLinesV(&A, fz_vec2(&r, 600), fz_count(&r, -4, 2048), fz_color(&r)); break;
        case 46: ImageDrawCircleGradient(&A, fz_vec2(&r, 600), fz_float(&r, -4, 300), fz_color(&r), fz_color(&r)); break;
        case 47: { Rectangle sr = fz_rect(&r, 600), dr = fz_rect(&r, 600); Vector2 o = fz_vec2(&r, 300); float rot = fz_float(&r, -720, 720); Color tn = fz_color(&r);
                   if (!fz_avoid_known() || (src_ok(B, sr) && (int)dr.width >= 1 && (int)dr.height >= 1)) ImageDrawImagePro(&A, B, sr, dr, o, rot, tn); } break;
        case 48: { Vector2 pos = fz_vec2(&r, 600); float rot = fz_float(&r, -720, 720), sc = fz_float(&r, -4, 8); Color tn = fz_color(&r);
                   if (!fz_avoid_known() || ((int)(B.width * sc) >= 1 && (int)(B.height * sc) >= 1)) ImageDrawImageEx(&A, B, pos, rot, sc, tn); } break;
        case 49: { Rectangle sr = fz_rect(&r, 600); Vector2 pos = fz_vec2(&r, 600); Color tn = fz_color(&r);
                   if (!fz_avoid_known() || src_ok(B, sr)) ImageDrawImageRec(&A, B, sr, pos, tn); } break;
        case 50: { char *s = fz_cstr(&r, 48); ImageDrawText(&A, s, fz_int_dom(&r, -100, 400, 1 << 16), fz_int_dom(&r, -100, 400, 1 << 16), fz_count(&r, -2, 256), fz_color(&r)); free(s); } break;
        case 51: { int es = 0; static const char *ex[] = { ".png", ".qoi", ".bmp", ".jpg", ".tga", ".dds" };
                   unsigned char *m = ExportImageToMemory(A, ex[fz_u8(&r) % 6], &es); MemFree(m); } break;
        }
    }
    UnloadImage(A); UnloadImage(B);
    return 0;
}
