/* Font loaders: stb_truetype (TTF/OTF, incl. SDF + bitmap rasterization) and raylib's BDF parser,
 * followed by atlas packing (stb_rect_pack + raylib's own packer) and text layout/rasterization.
 * Parameters come from the LAST 16 bytes of the input: TTF is offset-table addressed and BDF ends
 * at ENDFONT, so a trailer doesn't perturb parsing and raw font files work as seeds unchanged. */
#include "fuzz_common.h"
#ifndef FMT
#define FMT ".ttf"
#endif
FZ_USE_BINARY_MUTATOR

int LLVMFuzzerTestOneInput(const uint8_t *d, size_t n) {
    fz_init(FZ_GL);
    if (n < 16 || n > (4u << 20)) return 0;
    fz_rd r = { d + n - 16, 16 };
    int size = fz_int_edge(&r, 1, 96); if (size > 160) size = 160;      /* glyph raster cost ~ size^2 */
    int type = fz_range(&r, 0, 3);                                      /* DEFAULT, BITMAP, SDF, + invalid */
    int ncp = fz_range(&r, 0, 6);
    int cps[8]; for (int i = 0; i < ncp; i++) cps[i] = fz_int_edge(&r, 0, 0x2000);
    int pad = fz_count(&r, 0, 16), pack = fz_range(&r, 0, 1);
    if (fz_avoid_known()) {   /* KNOWN: duplicate codepoints => LoadFontFromMemory passes glyphCount > glyphs allocated */
        int k = 0; for (int i = 0; i < ncp; i++) { int dup = 0; for (int j = 0; j < k; j++) dup |= cps[j] == cps[i]; if (!dup) cps[k++] = cps[i]; }
        ncp = k; }
    const int *cpp = ncp ? cps : NULL;    /* NULL => default 95 ASCII glyphs */

    if (strcmp(FMT, ".bdf")) {
        int gc = 0;
        GlyphInfo *g = LoadFontData(d, (int)n, size, cpp, ncp, type, &gc);
        if (g && gc > 0) {
            Rectangle *recs = NULL;
            Image atlas = GenImageFontAtlas(g, &recs, gc, size, pad, pack);
            UnloadImage(atlas); MemFree(recs);
        }
        UnloadFontData(g, gc);
        /* KNOWN: 0 glyphs found => GenImageFontAtlas promotes glyphCount 0 -> 95 and over-reads */
        if (gc == 0 && fz_avoid_known()) return 0;
    }
    Font f = LoadFontFromMemory(FMT, d, (int)n, size, cpp, ncp);
    if (IsFontValid(f)) {
        const char *s = "Ag!~ \xc3\xa9\xe2\x82\xac\n\tW";
        (void)MeasureTextEx(f, s, (float)size, 1.0f);
        Image im = ImageTextEx(f, s, (float)size, 2.0f, WHITE); UnloadImage(im);
        (void)GetGlyphIndex(f, cps[0]); (void)GetGlyphAtlasRec(f, 0x10ffff);
        BeginDrawing(); DrawTextEx(f, s, (Vector2){ 1, 1 }, (float)size, 0, WHITE); EndDrawing();
    }
    UnloadFont(f);
    return 0;
}
