#include "custom_alloc.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdarg.h>

bool g_force_malloc_fail = false;
void *custom_malloc(size_t sz) {
    // If sz > 256MB, simulate fuzz_alloc capping
    if (sz > (256u << 20)) return NULL;
    return malloc(sz);
}
void custom_free(void *ptr) {
    free(ptr);
}

void TraceLog(int logLevel, const char *text, ...) {
    va_list args;
    va_start(args, text);
    vprintf(text, args);
    printf("\n");
    va_end(args);
}
unsigned char *LoadFileData(const char *fileName, int *dataSize) {
    FILE *f = fopen(fileName, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    int sz = (int)ftell(f);
    fseek(f, 0, SEEK_SET);
    unsigned char *d = (unsigned char *)malloc(sz);
    if (d) fread(d, 1, sz, f);
    fclose(f);
    if (dataSize) *dataSize = sz;
    return d;
}
void UnloadFileData(unsigned char *data) { free(data); }
bool SaveFileData(const char *fileName, const void *data, int dataSize) { return false; }
bool SaveFileText(const char *fileName, const char *text) { return false; }
bool IsFileExtension(const char *fileName, const char *ext) { return false; }
const char *GetFileExtension(const char *fileName) { return ""; }
const char *GetFileNameWithoutExt(const char *fileName) { return ""; }

#include "raylib.h"

int main(int argc, char **argv) {
    if (argc < 2) {
        printf("Usage: %s <wav_crash_file>\n", argv[0]);
        return 1;
    }
    const char *path = argv[1];
    int size = 0;
    unsigned char *data = LoadFileData(path, &size);
    if (!data) {
        printf("Failed to load file: %s\n", path);
        return 1;
    }

    printf("Loaded %s (%d bytes)\n", path, size);
    Wave w = LoadWaveFromMemory(".wav", data, size);
    printf("Wave loaded: frameCount=%u, channels=%u, sampleSize=%u, sampleRate=%u, data=%p\n",
           w.frameCount, w.channels, w.sampleSize, w.sampleRate, w.data);

    printf("Calling LoadWaveSamples(w)...\n");
    float *samples = LoadWaveSamples(w);
    printf("LoadWaveSamples returned: %p\n", (void*)samples);
    if (samples) {
        UnloadWaveSamples(samples);
        printf("Unloaded samples successfully.\n");
    } else {
        printf("Returned NULL safely (prevented crash)!\n");
    }

    UnloadWave(w);
    UnloadFileData(data);
    printf("SUCCESS: No crash in LoadWaveSamples for %s\n", path);
    return 0;
}

