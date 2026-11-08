/* Shared harness runtime (Drogon port). Same reader / structure-aware mutator / oracle design as
 * the raylib fuzzer's common/fuzz_common.h, with the raylib-specific pieces (raylib.h types, the
 * file-callback VFS mount, GL init) removed. Compiled as C so it shares common/fuzz_ucb.c with the
 * raylib tree byte-for-byte; the C++ harnesses include it through `extern "C"`. */
#ifndef FUZZ_COMMON_H
#define FUZZ_COMMON_H
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---------- FuzzedDataProvider-lite (identical to the raylib tree) ----------
 * Parameters are consumed from the FRONT; bulk payload is whatever is left. An exhausted reader
 * returns zeros, so every input is valid. */
typedef struct { const uint8_t *p; size_t n; } fz_rd;
static inline uint8_t  fz_u8(fz_rd *r)  { if (!r->n) return 0; r->n--; return *r->p++; }
static inline uint16_t fz_u16(fz_rd *r) { return (uint16_t)(fz_u8(r) | fz_u8(r) << 8); }
static inline uint32_t fz_u32(fz_rd *r) { return fz_u16(r) | (uint32_t)fz_u16(r) << 16; }
static inline int fz_range(fz_rd *r, int lo, int hi) {   /* inclusive, hi>=lo */
    uint32_t span = (uint32_t)(hi - lo) + 1u; return span ? lo + (int)(fz_u32(r) % span) : (int)fz_u32(r); }
int   fz_int_edge(fz_rd *r, int lo, int hi);             /* biased toward lo,hi,0,±1,powers of two, overflow edges */
const uint8_t *fz_bytes(fz_rd *r, size_t want, size_t *got);
char *fz_cstr(fz_rd *r, size_t maxlen);                  /* malloc'd NUL-terminated copy (u8 length prefix) */

/* ---------- generic length-prefixed container (multi-part inputs) ----------
 * Container: repeat { u8 nameLen; char name[nameLen]; u32le len; u8 data[len] }. Entry 0 is the
 * entry point. Lengths are clamped so truncated/mutated containers still parse. Used by the
 * multipart harness (several body parts) the way raylib used it for gltf+bin+png. */
#define FZ_VFS_MAX 12
typedef struct { char name[64]; const uint8_t *data; uint32_t len; } fz_file;
int    fz_vfs_parse(const uint8_t *d, size_t n, fz_file *out, int max);
size_t fz_vfs_serialize(const fz_file *f, int count, uint8_t *out, size_t max);

/* ---------- structure-aware mutators (UCB-scheduled; see common/fuzz_ucb.h) ----------
 * binary: libFuzzer mutate + integer-boundary injection + block duplication, then a probabilistic
 *         length-field FIXUP (Content-Length / chunk-size / WebSocket frame length) so mutants pass
 *         framing checks and reach deep parser states, while half stay inconsistent to test them. */
size_t fz_mutate_binary(uint8_t *d, size_t n, size_t max, unsigned seed);
size_t fz_mutate_vfs(uint8_t *d, size_t n, size_t max, unsigned seed);
size_t fz_cross_vfs(const uint8_t *a, size_t an, const uint8_t *b, size_t bn, uint8_t *o, size_t m, unsigned s);
void   fz_fixup(uint8_t *d, size_t n);

/* libFuzzer resolves LLVMFuzzerCustomMutator/CrossOver by C symbol name, so in a C++ harness these
 * must have C linkage (FZ_C) or they'd be name-mangled and silently ignored. */
#ifdef __cplusplus
#define FZ_C extern "C"
#else
#define FZ_C
#endif
#define FZ_USE_BINARY_MUTATOR \
    FZ_C size_t LLVMFuzzerCustomMutator(uint8_t *d, size_t n, size_t m, unsigned s) { return fz_mutate_binary(d, n, m, s); }
#define FZ_USE_VFS_MUTATOR \
    FZ_C size_t LLVMFuzzerCustomMutator(uint8_t *d, size_t n, size_t m, unsigned s) { return fz_mutate_vfs(d, n, m, s); } \
    FZ_C size_t LLVMFuzzerCustomCrossOver(const uint8_t *a, size_t an, const uint8_t *b, size_t bn, uint8_t *o, size_t m, unsigned s) \
        { return fz_cross_vfs(a, an, b, bn, o, m, s); }

/* ---------- oracle (semantic bugs that don't crash) ---------- */
int  fz_oracle_on(void);
int  fz_avoid_known(void);     /* FUZZ_KNOWN=1 re-enables known-bug paths (regression checking) */
void fz_oracle_fail(const char *msg, const char *f, int l);
#define FUZZ_ORACLE(c, msg) do { if (fz_oracle_on() && !(c)) { fz_oracle_fail(msg, __FILE__, __LINE__); } } while (0)

#ifdef __cplusplus
}  /* extern "C" */
#endif
#endif
