/* Image decoders: stb_image (png/bmp/tga/jpg/gif/pic/psd/hdr/pnm), qoi, and raylib's own
 * rl_gputex DDS/PKM/KTX/PVR/ASTC parsers. Built once per FMT so each binary has a pure corpus.
 * Beyond crash-finding it checks:
 *   - allocation-vs-header consistency (touch last byte of GetPixelDataSize() => ASan if short)
 *   - PNG export/import round-trip identity on RGBA8 (semantic oracle on stb_image_write + stbi)
 *   - GPU upload through rlsw (compressed-format texture paths, mip chains) */
#include "fuzz_common.h"
#include <stdlib.h>
#ifndef FMT
#define FMT ".png"
#endif
FZ_USE_BINARY_MUTATOR

static void touch_last(const Image *im) {
    int sz = GetPixelDataSize(im->width, im->height, im->format);
    if (sz > 0 && im->data) { volatile unsigned char x = ((unsigned char *)im->data)[sz - 1]; (void)x; }
}

int LLVMFuzzerTestOneInput(const uint8_t *d, size_t n) {
    fz_init(FZ_GL);
    if (n > (8u << 20)) return 0;

    /* Private exact-size copy: OOB reads hit ASan redzones, and we can detect decoders that write
     * into the caller's const buffer (KNOWN: rl_gputex PKM path byte-swaps its header in place). */
    unsigned char *buf = malloc(n ? n : 1); memcpy(buf, d, n);
    Image img = LoadImageFromMemory(FMT, buf, (int)n);
    if (memcmp(buf, d, n)) {
        static int once; if (!once++) fprintf(stderr, "==FUZZ FINDING== %s decoder modified its const input buffer\n", FMT);
        FUZZ_ORACLE(fz_avoid_known(), "decoder wrote to const input");
    }
    if (IsImageValid(img)) {
        FUZZ_ORACLE(img.width > 0 && img.height > 0 && img.mipmaps >= 1, "IsImageValid accepted bad dims");
        touch_last(&img);
        if ((long long)img.width * img.height <= FZ_PIXEL_CAP) {
            Texture2D t = LoadTextureFromImage(img);          /* rlsw texture conversion paths */
            if (IsTextureValid(t)) { Image back = LoadImageFromTexture(t); UnloadImage(back); }
            UnloadTexture(t);
            if (img.format < PIXELFORMAT_COMPRESSED_DXT1_RGB) {
                Color *c = LoadImageColors(img); UnloadImageColors(c);
                Image rgba = ImageCopy(img);
                ImageFormat(&rgba, PIXELFORMAT_UNCOMPRESSED_R8G8B8A8);
                if (rgba.format == PIXELFORMAT_UNCOMPRESSED_R8G8B8A8 && rgba.data) {
                    int es = 0; unsigned char *png = ExportImageToMemory(rgba, ".png", &es);
                    if (png) {
                        Image rt = LoadImageFromMemory(".png", png, es);
                        FUZZ_ORACLE(rt.width == rgba.width && rt.height == rgba.height, "png round-trip dims differ");
                        if (rt.format == rgba.format && rt.width == rgba.width && rt.height == rgba.height)
                            FUZZ_ORACLE(!memcmp(rt.data, rgba.data, (size_t)rgba.width * rgba.height * 4), "png round-trip pixels differ");
                        UnloadImage(rt); MemFree(png);
                    }
                }
                UnloadImage(rgba);
            }
        }
    }
    UnloadImage(img);

    if (!strcmp(FMT, ".gif")) {   /* animated path: frames appended vertically */
        int frames = 0; Image a = LoadImageAnimFromMemory(FMT, buf, (int)n, &frames);
        if (IsImageValid(a)) touch_last(&a);
        UnloadImage(a);
    }
    free(buf);
    return 0;
}
