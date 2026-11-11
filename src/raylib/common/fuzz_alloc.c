#include <stdlib.h>
#include <stdint.h>
#include "fuzz_alloc.h"

static size_t cap(void) {
    static size_t c;
    if (!c) { const char *e = getenv("FUZZ_MAX_ALLOC_MB"); c = (size_t)(e ? atol(e) : 256) << 20; }
    return c;
}
void *fz_malloc(size_t n) { return n > cap() ? NULL : malloc(n); }
void *fz_calloc(size_t n, size_t m) {
    if (m && n > SIZE_MAX / m) return NULL;           /* overflow => NULL, like a hardened libc */
    return n * m > cap() ? NULL : calloc(n, m);
}
void *fz_realloc(void *p, size_t n) { return n > cap() ? NULL : realloc(p, n); }
void  fz_free(void *p) { free(p); }
