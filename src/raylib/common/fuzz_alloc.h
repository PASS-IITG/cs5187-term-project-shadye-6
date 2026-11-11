/* Force-included into every TU (-include). Routes raylib/stb/dr_* allocations through a capped
 * allocator so a 4-byte header claiming a 2^31 pixel image returns NULL (realistic failure path)
 * instead of tripping libFuzzer's -malloc_limit_mb and drowning real bugs in OOM reports.
 * Cap: env FUZZ_MAX_ALLOC_MB (default 256). */
#ifndef FUZZ_ALLOC_H
#define FUZZ_ALLOC_H
#include <stddef.h>
void *fz_malloc(size_t n);
void *fz_calloc(size_t n, size_t m);
void *fz_realloc(void *p, size_t n);
void  fz_free(void *p);
#define RL_MALLOC(sz)      fz_malloc(sz)
#define RL_CALLOC(n, sz)   fz_calloc(n, sz)
#define RL_REALLOC(p, sz)  fz_realloc(p, sz)
#define RL_FREE(p)         fz_free(p)
#endif
