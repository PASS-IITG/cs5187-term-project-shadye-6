/* Drogon port of common/fuzz_common.c. The reader, container, UCB-scheduled binary/VFS mutators and
 * oracle are the same engine as the raylib tree; only fz_fixup is retargeted from image/audio
 * length fields to HTTP framing (Content-Length). Compiled as C; shares common/fuzz_ucb.c. */
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include "fuzz_common.h"
#include "fuzz_ucb.h"

/* ================= reader (identical to raylib tree) ================= */
int fz_int_edge(fz_rd *r, int lo, int hi) {
    static const int edge[] = { 0, 1, -1, 2, 3, 7, 8, 15, 16, 255, 256, 4095, 4096, 32767, 32768,
                                65535, 65536, 0x7fffffff, (int)0x80000000, 46341 /* sqrt(2^31) */ };
    uint8_t t = fz_u8(r);
    int v;
    if (t < 160) return fz_range(r, lo, hi);
    else if (t < 200) v = edge[fz_u8(r) % (sizeof edge / sizeof *edge)];
    else if (t < 230) v = 1 << (fz_u8(r) % 31);
    else v = (t & 1) ? lo : hi;
    return v;   /* edge values may lie outside [lo,hi] on purpose */
}

const uint8_t *fz_bytes(fz_rd *r, size_t want, size_t *got) {
    size_t k = want < r->n ? want : r->n; const uint8_t *p = r->p; r->p += k; r->n -= k; *got = k; return p;
}

char *fz_cstr(fz_rd *r, size_t maxlen) {
    size_t want = fz_u8(r); if (want > maxlen) want = maxlen;
    size_t got; const uint8_t *p = fz_bytes(r, want, &got);
    char *s = (char *)malloc(got + 1); memcpy(s, p, got); s[got] = 0; return s;
}

/* ================= oracle ================= */
int fz_avoid_known(void) { static int v = -1; if (v < 0) v = getenv("FUZZ_KNOWN") == NULL; return v; }
int fz_oracle_on(void)   { static int v = -1; if (v < 0) v = getenv("FUZZ_NO_ORACLE") == NULL; return v; }
void fz_oracle_fail(const char *msg, const char *f, int l) {
    fprintf(stderr, "==FUZZ ORACLE== %s at %s:%d\n", msg, f, l); fflush(stderr); abort();
}

/* ================= generic container ================= */
int fz_vfs_parse(const uint8_t *d, size_t n, fz_file *out, int max) {
    int c = 0; size_t i = 0;
    while (c < max && i < n) {
        size_t nl = d[i++]; if (nl > 63) nl = 63; if (nl > n - i) nl = n - i;
        memcpy(out[c].name, d + i, nl); out[c].name[nl] = 0; i += nl;
        for (size_t k = 0; k < nl; k++) if (!out[c].name[k] || out[c].name[k] == '/') out[c].name[k] = '_';
        uint32_t len = 0;
        for (int b = 0; b < 4 && i < n; b++) len |= (uint32_t)d[i++] << (8 * b);
        if (len > n - i) len = (uint32_t)(n - i);
        out[c].data = d + i; out[c].len = len; i += len; c++;
    }
    return c;
}
size_t fz_vfs_serialize(const fz_file *f, int count, uint8_t *out, size_t max) {
    size_t o = 0;
    for (int c = 0; c < count; c++) {
        size_t nl = strlen(f[c].name);
        if (o + 1 + nl + 4 > max) break;
        out[o++] = (uint8_t)nl; memcpy(out + o, f[c].name, nl); o += nl;
        uint32_t len = f[c].len; if (len > max - o - 4) len = (uint32_t)(max - o - 4);
        for (int b = 0; b < 4; b++) out[o++] = (uint8_t)(len >> (8 * b));
        memmove(out + o, f[c].data, len); o += len;
    }
    return o;
}

/* ================= mutators ================= */
__attribute__((weak)) size_t LLVMFuzzerMutate(uint8_t *d, size_t n, size_t max);
static uint32_t rng(uint32_t *s) { *s ^= *s << 13; *s ^= *s >> 17; *s ^= *s << 5; return *s; }

static size_t base_mutate(uint8_t *d, size_t n, size_t max, uint32_t *s) {
    if (LLVMFuzzerMutate) return LLVMFuzzerMutate(d, n, max);
    if (!n) { if (!max) return 0; d[0] = (uint8_t)rng(s); return 1; }
    d[rng(s) % n] ^= (uint8_t)(1u << (rng(s) & 7)); return n;
}

/* HTTP framing fixup: rewrite a Content-Length value to match the actual body length, in place and
 * length-preserving (value is right-aligned, zero-padded into the existing digit field). Half the
 * time the caller skips this so framing-mismatch paths (smuggling, truncation) are still exercised. */
static int ci_eq(const uint8_t *p, const char *lit, size_t n) {
    for (size_t i = 0; i < n; i++) if (tolower(p[i]) != lit[i]) return 0; return 1;
}
void fz_fixup(uint8_t *d, size_t n) {
    /* locate end of headers */
    size_t he = 0;
    for (size_t i = 0; i + 3 < n; i++)
        if (d[i] == '\r' && d[i+1] == '\n' && d[i+2] == '\r' && d[i+3] == '\n') { he = i + 4; break; }
    if (!he) return;
    size_t body = n - he;
    /* find a "content-length:" header line within [0,he) */
    for (size_t i = 0; i + 15 < he; i++) {
        if ((i == 0 || d[i-1] == '\n') && ci_eq(d + i, "content-length:", 15)) {
            size_t j = i + 15;
            while (j < he && (d[j] == ' ' || d[j] == '\t')) j++;
            size_t ds = j;
            while (j < he && d[j] >= '0' && d[j] <= '9') j++;
            size_t width = j - ds;
            if (width == 0) return;
            char num[32]; int nn = snprintf(num, sizeof num, "%zu", body);
            if (nn <= 0 || (size_t)nn > width) return;   /* can't fit without changing length: leave inconsistent */
            size_t pad = width - (size_t)nn;
            for (size_t k = 0; k < pad; k++) d[ds + k] = '0';
            memcpy(d + ds + pad, num, (size_t)nn);
            return;
        }
    }
}

static size_t bin_intedge(uint8_t *d, size_t n, uint32_t *s) {
    static const uint32_t mag[] = { 0, 1, 0x7f, 0x80, 0xff, 0x100, 0x7fff, 0x8000, 0xffff, 0x10000,
                                    0x7fffffff, 0x80000000u, 0xffffffffu, 0x40000000, 0x3fffffff, 0x10001 };
    size_t lim = n < 512 ? n : 512; size_t w = (rng(s) & 1) ? 4 : 2; if (lim < w) return n;
    size_t off = rng(s) % (lim - w + 1); uint32_t v = mag[rng(s) % 16];
    int be = rng(s) & 1;
    for (size_t k = 0; k < w; k++) d[off + k] = (uint8_t)(v >> (8 * (be ? (w - 1 - k) : k)));
    return n;
}
static size_t bin_blockdup(uint8_t *d, size_t n, size_t max, uint32_t *s) {
    size_t len = 1 + rng(s) % (n < 256 ? n : 256), src = rng(s) % (n - len + 1), dst = rng(s) % (n + 1);
    if (n + len <= max) { memmove(d + dst + len, d + dst, n - dst); memmove(d + dst, d + (src >= dst ? src + len : src), len); n += len; }
    return n;
}

static size_t do_mutate_binary(uint8_t *d, size_t n, size_t max, uint32_t *s, int credit_ucb) {
    static const int all[] = { FZ_ARM_BIN_LIBFUZZER, FZ_ARM_BIN_INTEDGE, FZ_ARM_BIN_BLOCKDUP, FZ_ARM_BIN_FIXUP };
    int arm;
    if (!credit_ucb || !fz_ucb_enabled()) {
        uint32_t r = rng(s) % 100;
        arm = (r < 72 || n < 8) ? FZ_ARM_BIN_LIBFUZZER : r < 88 ? FZ_ARM_BIN_INTEDGE : FZ_ARM_BIN_BLOCKDUP;
    } else {
        arm = n < 8 ? FZ_ARM_BIN_LIBFUZZER : fz_ucb_select(all, 4);
    }
    if (credit_ucb) fz_ucb_begin(arm);
    int force_fixup = 0;
    switch (arm) {
        case FZ_ARM_BIN_INTEDGE:  n = bin_intedge(d, n, s); break;
        case FZ_ARM_BIN_BLOCKDUP: n = bin_blockdup(d, n, max, s); break;
        case FZ_ARM_BIN_FIXUP:    n = base_mutate(d, n, max, s); force_fixup = 1; break;
        default:                  n = base_mutate(d, n, max, s); break;
    }
    if (force_fixup || (rng(s) & 1)) fz_fixup(d, n);
    return n;
}

size_t fz_mutate_binary(uint8_t *d, size_t n, size_t max, unsigned seed) {
    uint32_t s = seed | 1; return do_mutate_binary(d, n, max, &s, 1);
}

static const char *k_names[] = { "part0", "part1", "field", "file", "a.txt", "b.bin", "x", "upload" };

size_t fz_mutate_vfs(uint8_t *d, size_t n, size_t max, unsigned seed) {
    uint32_t s = seed | 1; fz_file f[FZ_VFS_MAX]; int c = fz_vfs_parse(d, n, f, FZ_VFS_MAX);
    if (!c) return base_mutate(d, n, max, &s);
    uint8_t *tmp = (uint8_t *)malloc(max), *work = (uint8_t *)malloc(max); size_t used = 0;
    for (int i = 0; i < c; i++) used += 5 + strlen(f[i].name) + f[i].len;
    int i = rng(&s) % c;
    int cand[4], nc = 0; cand[nc++] = FZ_ARM_VFS_ENTRY; cand[nc++] = FZ_ARM_VFS_RENAME;
    if (c < FZ_VFS_MAX) cand[nc++] = FZ_ARM_VFS_DUP;
    if (c > 1) cand[nc++] = FZ_ARM_VFS_DROP;
    int arm;
    if (!fz_ucb_enabled()) {
        uint32_t r = rng(&s) % 100;
        arm = r < 80 ? FZ_ARM_VFS_ENTRY : r < 88 ? FZ_ARM_VFS_RENAME
            : (r < 94 && c < FZ_VFS_MAX) ? FZ_ARM_VFS_DUP : (c > 1 ? FZ_ARM_VFS_DROP : FZ_ARM_VFS_ENTRY);
    } else {
        arm = fz_ucb_select(cand, nc);
    }
    fz_ucb_begin(arm);
    if (arm == FZ_ARM_VFS_ENTRY) {
        size_t room = max > used ? max - used + f[i].len : f[i].len;
        memcpy(work, f[i].data, f[i].len);
        uint32_t s2 = rng(&s) | 1;
        size_t nl = do_mutate_binary(work, f[i].len, room, &s2, 0);   /* nested: VFS arm keeps credit */
        f[i].data = work; f[i].len = (uint32_t)nl;
    } else if (arm == FZ_ARM_VFS_RENAME) {
        snprintf(f[i].name, sizeof f[i].name, "%s", k_names[rng(&s) % 8]);
    } else if (arm == FZ_ARM_VFS_DUP && c < FZ_VFS_MAX) { f[c] = f[i]; c++; }
    else if (c > 1) { memmove(&f[i], &f[i + 1], (c - i - 1) * sizeof *f); c--; }
    size_t o = fz_vfs_serialize(f, c, tmp, max); memcpy(d, tmp, o);
    free(tmp); free(work); return o;
}

size_t fz_cross_vfs(const uint8_t *a, size_t an, const uint8_t *b, size_t bn, uint8_t *out, size_t max, unsigned seed) {
    uint32_t s = seed | 1; fz_file fa[FZ_VFS_MAX], fb[FZ_VFS_MAX];
    int ca = fz_vfs_parse(a, an, fa, FZ_VFS_MAX), cb = fz_vfs_parse(b, bn, fb, FZ_VFS_MAX);
    if (!ca || !cb) return 0;
    fz_ucb_begin(FZ_ARM_VFS_CROSS);
    int i = rng(&s) % ca, j = rng(&s) % cb;
    if ((rng(&s) & 3) == 0 && ca < FZ_VFS_MAX) fa[ca++] = fb[j];
    else { char nm[64]; memcpy(nm, fa[i].name, 64); fa[i] = fb[j]; memcpy(fa[i].name, nm, 64); }
    return fz_vfs_serialize(fa, ca, out, max);
}
