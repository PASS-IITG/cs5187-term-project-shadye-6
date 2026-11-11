#include <stdio.h>
#include <stdlib.h>
#include <float.h>
#include <math.h>
#include "fuzz_common.h"
#include "fuzz_ucb.h"

/* ================= reader ================= */
int fz_int_edge(fz_rd *r, int lo, int hi) {
    static const int edge[] = { 0, 1, -1, 2, 3, 7, 8, 15, 16, 255, 256, 4095, 4096, 32767, 32768,
                                65535, 65536, 0x7fffffff, (int)0x80000000, 46341 /* sqrt(2^31) */ };
    uint8_t t = fz_u8(r);
    int v;
    if (t < 160) return fz_range(r, lo, hi);
    else if (t < 200) v = edge[fz_u8(r) % (sizeof edge / sizeof *edge)];
    else if (t < 230) v = 1 << (fz_u8(r) % 31);
    else v = (t & 1) ? lo : hi;
    return v;   /* edge values may lie outside [lo,hi] on purpose: that is the point */
}

/* Default: finite, |x| <= 1e6, so (int)x is defined and findings are memory/logic bugs, not the
 * NaN->int UB cascade. FUZZ_NAN=1 (pair with STRICT_UB=1 build) adds NaN/Inf/FLT_MAX/raw bit patterns. */
static int nan_on(void) { static int v = -1; if (v < 0) v = getenv("FUZZ_NAN") != NULL; return v; }
float fz_float(fz_rd *r, float lo, float hi) {
    uint8_t t = fz_u8(r);
    if ((t & 7) == 0) {
        static const float sp[] = { 0.f, -0.f, NAN, INFINITY, -INFINITY, FLT_MAX, -FLT_MAX, 1e-40f /*denorm*/ };
        static const float sf[] = { 0.f, -0.f, 0.5f, -1.f, 1e6f, -1e6f, 1e-6f, 1e-40f };
        return (nan_on() ? sp : sf)[(t >> 3) & 7];
    }
    if ((t & 7) == 1) { uint32_t b = fz_u32(r); float f; memcpy(&f, &b, 4);       /* raw bit pattern */
        if (!nan_on() && !(f >= -1e6f && f <= 1e6f)) f = 0.f;  return f; }
    return lo + (hi - lo) * (fz_u16(r) / 65535.f);
}

const uint8_t *fz_bytes(fz_rd *r, size_t want, size_t *got) {
    size_t k = want < r->n ? want : r->n; const uint8_t *p = r->p; r->p += k; r->n -= k; *got = k; return p;
}

char *fz_cstr(fz_rd *r, size_t maxlen) {
    size_t want = fz_u8(r); if (want > maxlen) want = maxlen;
    size_t got; const uint8_t *p = fz_bytes(r, want, &got);
    char *s = malloc(got + 1); memcpy(s, p, got); s[got] = 0; return s;
}

/* ================= oracle ================= */
int fz_wide_int(void) { static int v = -1; if (v < 0) v = getenv("FUZZ_WIDE_INT") != NULL; return v; }
int fz_avoid_known(void) { static int v = -1; if (v < 0) v = getenv("FUZZ_KNOWN") == NULL; return v; }
int fz_oracle_on(void) { static int v = -1; if (v < 0) v = getenv("FUZZ_NO_ORACLE") == NULL; return v; }
void fz_oracle_fail(const char *msg, const char *f, int l) {
    fprintf(stderr, "==FUZZ ORACLE== %s at %s:%d\n", msg, f, l); fflush(stderr); abort();
}

/* ================= VFS ================= */
static const fz_file *g_vfs; static int g_vfs_n;

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

static const fz_file *vfs_find(const char *path) {
    if (!path) return NULL;
    const char *base = strrchr(path, '/'); base = base ? base + 1 : path;
    for (int i = 0; i < g_vfs_n; i++) if (!strcmp(g_vfs[i].name, path)) return &g_vfs[i];
    for (int i = 0; i < g_vfs_n; i++) if (!strcmp(g_vfs[i].name, base)) return &g_vfs[i];
    return NULL;
}
static unsigned char *cb_load_data(const char *fn, int *sz) {
    const fz_file *f = vfs_find(fn); *sz = 0; if (!f) return NULL;
    unsigned char *p = RL_MALLOC(f->len ? f->len : 1); memcpy(p, f->data, f->len); *sz = (int)f->len; return p;
}
static char *cb_load_text(const char *fn) {
    const fz_file *f = vfs_find(fn); if (!f) return NULL;
    char *p = RL_MALLOC(f->len + 1); memcpy(p, f->data, f->len); p[f->len] = 0; return p;
}
static bool cb_save_data(const char *fn, const void *d, int n) { (void)fn; (void)d; (void)n; return true; }
static bool cb_save_text(const char *fn, const char *t) { (void)fn; (void)t; return true; }

void fz_vfs_mount(const fz_file *f, int count) { g_vfs = f; g_vfs_n = count; }
void fz_vfs_unmount(void) { g_vfs = NULL; g_vfs_n = 0; }

/* ================= init ================= */
static void quiet_log(int lvl, const char *t, va_list a) { (void)lvl; (void)t; (void)a; }
void fz_init(int flags) {
    static int done = 0;
    if (!(done & 1)) {
        if (!getenv("FUZZ_LOG")) { SetTraceLogLevel(LOG_NONE); SetTraceLogCallback(quiet_log); } /* callback => LOG_FATAL won't exit() */
        SetLoadFileDataCallback(cb_load_data); SetLoadFileTextCallback(cb_load_text);
        SetSaveFileDataCallback(cb_save_data); SetSaveFileTextCallback(cb_save_text);
        done |= 1;
    }
    if ((flags & FZ_GL) && !(done & 2)) { InitWindow(64, 48, "fuzz"); done |= 2; }
    SetRandomSeed(0x5eed);   /* per-iteration determinism for GetRandomValue users */
}

/* ================= mutators ================= */
__attribute__((weak)) size_t LLVMFuzzerMutate(uint8_t *d, size_t n, size_t max);
static uint32_t rng(uint32_t *s) { *s ^= *s << 13; *s ^= *s >> 17; *s ^= *s << 5; return *s; }

static size_t base_mutate(uint8_t *d, size_t n, size_t max, uint32_t *s) {
    if (LLVMFuzzerMutate) return LLVMFuzzerMutate(d, n, max);
    if (!n) { if (!max) return 0; d[0] = (uint8_t)rng(s); return 1; }       /* standalone fallback */
    d[rng(s) % n] ^= (uint8_t)(1u << (rng(s) & 7)); return n;
}

static uint32_t rd32le(const uint8_t *p) { return p[0] | p[1] << 8 | p[2] << 16 | (uint32_t)p[3] << 24; }
static void wr32le(uint8_t *p, uint32_t v) { p[0] = v; p[1] = v >> 8; p[2] = v >> 16; p[3] = v >> 24; }

/* Rewrite length fields so the container is self-consistent after a mutation. */
void fz_fixup(uint8_t *d, size_t n) {
    if (n >= 12 && !memcmp(d, "RIFF", 4)) {                         /* WAV */
        wr32le(d + 4, (uint32_t)(n - 8));
        size_t i = 12;
        while (i + 8 <= n) { uint32_t cl = rd32le(d + i + 4);
            if (cl > n - i - 8) { wr32le(d + i + 4, (uint32_t)(n - i - 8)); break; }
            i += 8 + cl + (cl & 1); }
    } else if (n >= 20 && !memcmp(d, "VOX ", 4) && !memcmp(d + 8, "MAIN", 4)) {   /* MagicaVoxel */
        wr32le(d + 16, (uint32_t)(n - 20));
    } else if (n >= 20 && !memcmp(d, "glTF", 4)) {                  /* GLB: total + clamp JSON chunk */
        wr32le(d + 8, (uint32_t)n);
        if (rd32le(d + 12) > n - 20) wr32le(d + 12, (uint32_t)(n - 20));
    } else if (n >= 24 && !memcmp(d, "INTERQUAKEMODEL", 15)) {      /* IQM header.filesize */
        wr32le(d + 20, (uint32_t)n);
    }
}

/* --- individual binary strategies (each returns the new length) --- */
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

/* Core of the binary mutator. `credit_ucb` is 0 when invoked *inside* the VFS mutator, so the
 * VFS-level arm (entry/rename/dup/drop) keeps the coverage credit instead of this nested call. */
static size_t do_mutate_binary(uint8_t *d, size_t n, size_t max, uint32_t *s, int credit_ucb) {
    static const int all[] = { FZ_ARM_BIN_LIBFUZZER, FZ_ARM_BIN_INTEDGE, FZ_ARM_BIN_BLOCKDUP, FZ_ARM_BIN_FIXUP };
    int arm;
    if (!credit_ucb || !fz_ucb_enabled()) {   /* original fixed 72/16/12 split */
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
    if (force_fixup || (rng(s) & 1)) fz_fixup(d, n);  /* FIXUP arm always; others keep the 50% split */
    return n;
}

size_t fz_mutate_binary(uint8_t *d, size_t n, size_t max, unsigned seed) {
    uint32_t s = seed | 1; return do_mutate_binary(d, n, max, &s, 1);
}

static const char *k_names[] = { "a.gltf", "a.bin", "a.png", "a.mtl", "a.obj", "a_0.png", "tex.png", "a.fnt" };

size_t fz_mutate_vfs(uint8_t *d, size_t n, size_t max, unsigned seed) {
    uint32_t s = seed | 1; fz_file f[FZ_VFS_MAX]; int c = fz_vfs_parse(d, n, f, FZ_VFS_MAX);
    if (!c) return base_mutate(d, n, max, &s);
    uint8_t *tmp = malloc(max), *work = malloc(max); size_t used = 0;
    for (int i = 0; i < c; i++) used += 5 + strlen(f[i].name) + f[i].len;
    int i = rng(&s) % c;
    /* Candidate arms depend on the current container: drop needs >1 entry, dup needs headroom. */
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
    if (arm == FZ_ARM_VFS_ENTRY) {   /* mutate one entry's payload in a private buffer */
        size_t room = max > used ? max - used + f[i].len : f[i].len;
        memcpy(work, f[i].data, f[i].len);
        uint32_t s2 = rng(&s) | 1;
        size_t nl = do_mutate_binary(work, f[i].len, room, &s2, 0);   /* nested: VFS arm keeps credit */
        f[i].data = work; f[i].len = (uint32_t)nl;
    } else if (arm == FZ_ARM_VFS_RENAME) {      /* rename: break/redirect cross-file references */
        snprintf(f[i].name, sizeof f[i].name, "%s", k_names[rng(&s) % 8]);
    } else if (arm == FZ_ARM_VFS_DUP && c < FZ_VFS_MAX) { f[c] = f[i]; c++; }   /* duplicate entry */
    else if (c > 1) { memmove(&f[i], &f[i + 1], (c - i - 1) * sizeof *f); c--; } /* drop entry */
    size_t o = fz_vfs_serialize(f, c, tmp, max); memcpy(d, tmp, o);
    free(tmp); free(work); return o;
}

size_t fz_cross_vfs(const uint8_t *a, size_t an, const uint8_t *b, size_t bn, uint8_t *out, size_t max, unsigned seed) {
    uint32_t s = seed | 1; fz_file fa[FZ_VFS_MAX], fb[FZ_VFS_MAX];
    int ca = fz_vfs_parse(a, an, fa, FZ_VFS_MAX), cb = fz_vfs_parse(b, bn, fb, FZ_VFS_MAX);
    if (!ca || !cb) return 0;
    fz_ucb_begin(FZ_ARM_VFS_CROSS);
    int i = rng(&s) % ca, j = rng(&s) % cb;
    if ((rng(&s) & 3) == 0 && ca < FZ_VFS_MAX) fa[ca++] = fb[j];          /* graft */
    else { char nm[64]; memcpy(nm, fa[i].name, 64); fa[i] = fb[j]; memcpy(fa[i].name, nm, 64); } /* swap body, keep name */
    return fz_vfs_serialize(fa, ca, out, max);
}
