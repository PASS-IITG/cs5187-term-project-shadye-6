/* Shared harness runtime: input reader, one-time raylib init, in-memory VFS, custom mutators. */
#ifndef FUZZ_COMMON_H
#define FUZZ_COMMON_H
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include "raylib.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

/* ---------- init ---------- */
enum { FZ_GL = 1 };          /* FZ_GL: InitWindow() on PLATFORM_MEMORY + rlsw software renderer */
void fz_init(int flags);     /* idempotent; silences TraceLog (set FUZZ_LOG=1 to see it), installs VFS */
#define FZ_PIXEL_CAP (1 << 22)   /* harness-side cap on w*h before *growing* ops (4M px) */

/* ---------- FuzzedDataProvider-lite ----------
 * Parameters are consumed from the FRONT; bulk payload is whatever is left (fz_rest).
 * Exhausted reader returns zeros, so every input is valid. */
typedef struct { const uint8_t *p; size_t n; } fz_rd;
static inline uint8_t  fz_u8(fz_rd *r)  { if (!r->n) return 0; r->n--; return *r->p++; }
static inline uint16_t fz_u16(fz_rd *r) { return (uint16_t)(fz_u8(r) | fz_u8(r) << 8); }
static inline uint32_t fz_u32(fz_rd *r) { return fz_u16(r) | (uint32_t)fz_u16(r) << 16; }
static inline int fz_range(fz_rd *r, int lo, int hi) {  /* inclusive, hi>=lo */
    uint32_t span = (uint32_t)(hi - lo) + 1u; return span ? lo + (int)(fz_u32(r) % span) : (int)fz_u32(r); }
int   fz_int_edge(fz_rd *r, int lo, int hi);   /* biased toward lo,hi,0,±1,powers of two, overflow edges */
float fz_float(fz_rd *r, float lo, float hi);
static inline int fz_count(fz_rd *r, int lo, int hi) {     /* edge-biased but clamped: loop bounds (avoid DoS-only hangs) */
    int v = fz_int_edge(r, lo, hi); return v < lo ? lo : v > hi ? hi : v; }
/* Known, already-reported bugs: avoided by default so campaigns keep finding NEW ones.
 * FUZZ_KNOWN=1 re-enables them (regression checking / confirming a fix). See README §Findings. */
int fz_avoid_known(void);
/* Coordinate-domain ints: edge-biased, but clamped to +-dom unless FUZZ_WIDE_INT=1, so INT_MAX
 * positions don't flood triage with "x + w overflows" UB that no real caller produces. */
int fz_wide_int(void);
static inline int fz_int_dom(fz_rd *r, int lo, int hi, int dom) {
    int v = fz_int_edge(r, lo, hi); if (fz_wide_int()) return v; return v < -dom ? -dom : v > dom ? dom : v; }  /* 1/8 chance of NaN/Inf/-0/denorm/FLT_MAX, else in [lo,hi] */
static inline Color fz_color(fz_rd *r) { Color c; uint32_t v = fz_u32(r); memcpy(&c, &v, 4); return c; }
static inline Vector2 fz_vec2(fz_rd *r, float m) { Vector2 v = { fz_float(r, -m, m), fz_float(r, -m, m) }; return v; }
static inline Rectangle fz_rect(fz_rd *r, float m) {
    Rectangle q = { fz_float(r, -m, m), fz_float(r, -m, m), fz_float(r, -m, m), fz_float(r, -m, m) }; return q; }
const uint8_t *fz_bytes(fz_rd *r, size_t want, size_t *got);   /* length-prefixed-free slice */
char *fz_cstr(fz_rd *r, size_t maxlen);  /* malloc'd NUL-terminated copy (u8 length prefix) */

/* ---------- in-memory VFS (multi-file formats: gltf+bin+png, obj+mtl, fnt+png) ----------
 * Container: repeat { u8 nameLen; char name[nameLen]; u32le len; u8 data[len] }. Entry 0 is the
 * entry point. Lengths are clamped, so truncated/mutated containers still parse. raylib's
 * LoadFileData/LoadFileText callbacks resolve by full path, then basename. Saves are discarded. */
#define FZ_VFS_MAX 12
typedef struct { char name[64]; const uint8_t *data; uint32_t len; } fz_file;
int  fz_vfs_parse(const uint8_t *d, size_t n, fz_file *out, int max);
void fz_vfs_mount(const fz_file *f, int count);   /* point raylib file callbacks at these entries */
void fz_vfs_unmount(void);
size_t fz_vfs_serialize(const fz_file *f, int count, uint8_t *out, size_t max);

/* ---------- structure-aware mutators ----------
 * binary: libFuzzer mutate + integer-boundary injection in headers + block duplication, then a
 *         probabilistic length-field FIXUP for RIFF(WAV)/VOX/GLB/IQM so mutants pass size checks
 *         and reach deep parser code instead of dying on the first sanity check.
 * vfs:    entry-aware: mutate one file's bytes, rename/duplicate/drop entries; crossover swaps
 *         whole entries between corpus items. */
size_t fz_mutate_binary(uint8_t *d, size_t n, size_t max, unsigned seed);
size_t fz_mutate_vfs(uint8_t *d, size_t n, size_t max, unsigned seed);
size_t fz_cross_vfs(const uint8_t *a, size_t an, const uint8_t *b, size_t bn, uint8_t *out, size_t max, unsigned seed);
void   fz_fixup(uint8_t *d, size_t n);

#define FZ_USE_BINARY_MUTATOR \
    size_t LLVMFuzzerCustomMutator(uint8_t *d, size_t n, size_t m, unsigned s) { return fz_mutate_binary(d, n, m, s); }
#define FZ_USE_VFS_MUTATOR \
    size_t LLVMFuzzerCustomMutator(uint8_t *d, size_t n, size_t m, unsigned s) { return fz_mutate_vfs(d, n, m, s); } \
    size_t LLVMFuzzerCustomCrossOver(const uint8_t *a, size_t an, const uint8_t *b, size_t bn, uint8_t *o, size_t m, unsigned s) \
        { return fz_cross_vfs(a, an, b, bn, o, m, s); }

/* Oracle: FUZZ_ORACLE(cond) aborts on a semantic violation (a bug even without memory corruption).
 * Disable with env FUZZ_NO_ORACLE=1 while triaging memory-safety only. */
int fz_oracle_on(void);
#define FUZZ_ORACLE(c, msg) do { if (fz_oracle_on() && !(c)) { fz_oracle_fail(msg, __FILE__, __LINE__); } } while (0)
void fz_oracle_fail(const char *msg, const char *f, int l);
#endif
