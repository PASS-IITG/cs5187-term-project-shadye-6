#ifndef CUSTOM_ALLOC_H
#define CUSTOM_ALLOC_H

#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

extern bool g_force_malloc_fail;
void *custom_malloc(size_t sz);
void custom_free(void *ptr);

#define RL_MALLOC(sz) custom_malloc(sz)
#define RL_FREE(ptr) custom_free(ptr)

#ifdef __cplusplus
}
#endif

#endif // CUSTOM_ALLOC_H

