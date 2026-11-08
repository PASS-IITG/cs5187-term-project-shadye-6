/* rtext string API + rcore path helpers. Most of these return pointers into fixed static buffers
 * (MAX_TEXT_BUFFER_LENGTH etc.), so the bug class is length arithmetic against those buffers.
 * Oracles: UTF-8 encode/decode idempotence, TextLength == strlen, split/join consistency. */
#include "fuzz_common.h"
#include <stdlib.h>

int LLVMFuzzerTestOneInput(const uint8_t *d, size_t n) {
    fz_init(FZ_GL);                       /* MeasureTextEx/ImageTextEx need the default font */
    fz_rd r = { d, n };
    char *a = fz_cstr(&r, 255), *b = fz_cstr(&r, 64), *c = fz_cstr(&r, 64);
    size_t got; const uint8_t *rest = fz_bytes(&r, 4096, &got);
    char *t = malloc(got + 1); memcpy(t, rest, got); t[got] = 0;          /* big string: may exceed static buffers */
    const char *strs[] = { a, t };

    for (int k = 0; k < 2; k++) {
        const char *s = strs[k];
        FUZZ_ORACLE(TextLength(s) == strlen(s), "TextLength != strlen");
        /* UTF-8: decode -> encode -> decode must be a fixed point */
        int cnt = 0; int *cps = LoadCodepoints(s, &cnt);
        if (cps) {
            char *u = LoadUTF8(cps, cnt);
            if (u) { int cnt2 = 0; int *cps2 = LoadCodepoints(u, &cnt2);
                FUZZ_ORACLE(cnt2 == cnt && (!cnt || !memcmp(cps, cps2, cnt * sizeof(int))), "UTF-8 round-trip not idempotent");
                UnloadCodepoints(cps2); UnloadUTF8(u); }
            UnloadCodepoints(cps);
        }
        (void)GetCodepointCount(s);
        int sz = 0, len = (int)strlen(s);
        for (const char *p = s; *p; p += sz > 0 ? sz : 1) (void)GetCodepointNext(p, &sz);
        if (len) for (const char *p = s + len; p > s; ) { (void)GetCodepointPrevious(p, &sz); p -= sz > 0 ? sz : 1; }

        (void)TextSubtext(s, fz_int_edge(&r, -8, len + 8), fz_int_edge(&r, -8, len + 8));
        (void)TextFindIndex(s, b);
        (void)TextReplace(s, b, c);
        char *ra = TextReplaceAlloc(s, b, c); MemFree(ra);
        (void)TextReplaceBetween(s, b, c, a);
        char *rb = TextReplaceBetweenAlloc(s, b, c, a); MemFree(rb);
        (void)TextInsert(s, b, fz_int_edge(&r, -8, len + 8));
        char *ia = TextInsertAlloc(s, b, fz_int_edge(&r, -8, len + 8)); MemFree(ia);
        char *gb = GetTextBetween(s, b, c); (void)gb;
        (void)TextRemoveSpaces(s);
        (void)TextToUpper(s); (void)TextToLower(s); (void)TextToPascal(s); (void)TextToSnake(s); (void)TextToCamel(s);
        (void)TextToInteger(s); (void)TextToFloat(s); (void)TextIsEqual(s, b);

        int parts = 0; char **sp = TextSplit(s, b[0] ? b[0] : ',', &parts);
        if (sp && parts > 0) (void)TextJoin(sp, parts, c);
        int lines = 0; char **ln = LoadTextLines(s, &lines); UnloadTextLines(ln, lines);

        (void)GetFileName(s); (void)GetFileNameWithoutExt(s); if (s[0] || !fz_avoid_known()) (void)GetDirectoryPath(s);   /* KNOWN: reads filePath[1] past NUL on "" */
        (void)GetPrevDirectoryPath(s); (void)GetFileExtension(s); (void)IsFileExtension(s, b); (void)IsFileNameValid(s);

        (void)MeasureTextEx(GetFontDefault(), s, fz_float(&r, -10, 100), fz_float(&r, -10, 20));
        if (k == 0) { Image im = ImageTextEx(GetFontDefault(), s, (float)fz_range(&r, 1, 40), (float)fz_range(&r, fz_avoid_known() ? 0 : -4, 8), WHITE)   /* KNOWN: spacing<0 => width 0 => ImageResizeNN div-by-zero */; UnloadImage(im); }
    }
    for (int i = 0; i < 4; i++) { int u = 0; (void)CodepointToUTF8(fz_int_edge(&r, -2, 0x110000), &u); }

    char buf[512] = { 0 }; int pos = 0;            /* TextAppend: caller-sized buffer, append bounded by us */
    if (strlen(b) + strlen(c) < sizeof buf) { TextAppend(buf, b, &pos); TextAppend(buf, c, &pos); }

    free(a); free(b); free(c); free(t);
    return 0;
}
