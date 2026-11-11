#include "custom_alloc.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdarg.h>
#include <math.h>

bool g_force_malloc_fail = false;
void *custom_malloc(size_t sz) {
    if (g_force_malloc_fail) return NULL;
    return malloc(sz);
}
void custom_free(void *ptr) {
    free(ptr);
}

// Stubs for raylib core functions referenced by raudio.c
void TraceLog(int logLevel, const char *text, ...) {
    va_list args;
    va_start(args, text);
    vprintf(text, args);
    printf("\n");
    va_end(args);
}
unsigned char *LoadFileData(const char *fileName, int *dataSize) { return NULL; }
void UnloadFileData(unsigned char *data) {}
bool SaveFileData(const char *fileName, const void *data, int dataSize) { return false; }
bool SaveFileText(const char *fileName, const char *text) { return false; }
bool IsFileExtension(const char *fileName, const char *ext) { return false; }
const char *GetFileExtension(const char *fileName) { return ""; }
const char *GetFileNameWithoutExt(const char *fileName) { return ""; }

#include "raylib.h"

int main(int argc, char **argv) {
    int test_num = (argc > 1) ? atoi(argv[1]) : 0;
    printf("--- Running LoadWaveSamples Test %d ---\n", test_num);

    if (test_num == 1) {
        // Test 1: Valid 8-bit, 16-bit, 32-bit waves
        printf("Subtest 1a: Valid 8-bit WAV\n");
        unsigned char raw8[] = { 0, 128, 255, 64 };
        Wave w8 = { .data = raw8, .frameCount = 4, .sampleRate = 44100, .sampleSize = 8, .channels = 1 };
        float *s8 = LoadWaveSamples(w8);
        if (!s8) { printf("FAIL: NULL returned for valid 8-bit wave\n"); return 1; }
        printf("  Sample 0: %.3f (expected -1.0)\n", s8[0]);
        printf("  Sample 1: %.3f (expected 0.0)\n", s8[1]);
        if (fabs(s8[0] - (-1.0f)) > 0.01f || fabs(s8[1] - 0.0f) > 0.01f) {
            printf("FAIL: Value mismatch in 8-bit\n");
            UnloadWaveSamples(s8);
            return 1;
        }
        UnloadWaveSamples(s8);

        printf("Subtest 1b: Valid 16-bit WAV\n");
        short raw16[] = { -32768, 0, 16384 };
        Wave w16 = { .data = raw16, .frameCount = 3, .sampleRate = 44100, .sampleSize = 16, .channels = 1 };
        float *s16 = LoadWaveSamples(w16);
        if (!s16) { printf("FAIL: NULL returned for valid 16-bit wave\n"); return 1; }
        printf("  Sample 0: %.3f (expected -1.0)\n", s16[0]);
        printf("  Sample 1: %.3f (expected 0.0)\n", s16[1]);
        printf("  Sample 2: %.3f (expected 0.5)\n", s16[2]);
        if (fabs(s16[0] - (-1.0f)) > 0.01f || fabs(s16[1] - 0.0f) > 0.01f || fabs(s16[2] - 0.5f) > 0.01f) {
            printf("FAIL: Value mismatch in 16-bit\n");
            UnloadWaveSamples(s16);
            return 1;
        }
        UnloadWaveSamples(s16);

        printf("Subtest 1c: Valid 32-bit WAV\n");
        float raw32[] = { -0.75f, 0.0f, 0.25f };
        Wave w32 = { .data = raw32, .frameCount = 3, .sampleRate = 44100, .sampleSize = 32, .channels = 1 };
        float *s32 = LoadWaveSamples(w32);
        if (!s32) { printf("FAIL: NULL returned for valid 32-bit wave\n"); return 1; }
        printf("  Sample 0: %.3f (expected -0.75)\n", s32[0]);
        printf("  Sample 1: %.3f (expected 0.0)\n", s32[1]);
        printf("  Sample 2: %.3f (expected 0.25)\n", s32[2]);
        if (fabs(s32[0] - (-0.75f)) > 0.001f || fabs(s32[1] - 0.0f) > 0.001f || fabs(s32[2] - 0.25f) > 0.001f) {
            printf("FAIL: Value mismatch in 32-bit\n");
            UnloadWaveSamples(s32);
            return 1;
        }
        UnloadWaveSamples(s32);
        printf("RESULT: PASS - Test 1 (Valid 8-bit, 16-bit, 32-bit WAVs converted correctly)\n");
    }
    else if (test_num == 2) {
        // Test 2: Allocation forced to fail
        short raw16[] = { 100, 200, 300, 400 };
        Wave w = { .data = raw16, .frameCount = 4, .sampleRate = 44100, .sampleSize = 16, .channels = 1 };
        g_force_malloc_fail = true;
        printf("  Calling LoadWaveSamples with forced malloc failure...\n");
        float *s = LoadWaveSamples(w);
        g_force_malloc_fail = false;
        if (s != NULL) {
            printf("FAIL: Expected NULL when allocation fails, got %p\n", (void*)s);
            UnloadWaveSamples(s);
            return 1;
        }
        printf("RESULT: PASS - Test 2 (Allocation forced to fail: returned NULL, no sanitizer error)\n");
    }
    else if (test_num == 3) {
        // Test 3: Missing wave.data
        Wave w = { .data = NULL, .frameCount = 100, .sampleRate = 44100, .sampleSize = 16, .channels = 2 };
        printf("  Calling LoadWaveSamples with wave.data == NULL...\n");
        float *s = LoadWaveSamples(w);
        if (s != NULL) {
            printf("FAIL: Expected NULL for wave.data == NULL, got %p\n", (void*)s);
            UnloadWaveSamples(s);
            return 1;
        }
        printf("RESULT: PASS - Test 3 (Missing wave.data: returned NULL)\n");
    }
    else if (test_num == 4) {
        // Test 4: Zero channels / zero frames
        short raw16[] = { 10, 20 };
        printf("Subtest 4a: wave.channels == 0\n");
        Wave w_ch0 = { .data = raw16, .frameCount = 2, .sampleRate = 44100, .sampleSize = 16, .channels = 0 };
        float *s_ch0 = LoadWaveSamples(w_ch0);
        if (s_ch0 != NULL) {
            printf("FAIL: Expected NULL for channels = 0, got %p\n", (void*)s_ch0);
            UnloadWaveSamples(s_ch0);
            return 1;
        }

        printf("Subtest 4b: wave.frameCount == 0\n");
        Wave w_fc0 = { .data = raw16, .frameCount = 0, .sampleRate = 44100, .sampleSize = 16, .channels = 1 };
        float *s_fc0 = LoadWaveSamples(w_fc0);
        if (s_fc0 != NULL) {
            printf("FAIL: Expected NULL for frameCount = 0, got %p\n", (void*)s_fc0);
            UnloadWaveSamples(s_fc0);
            return 1;
        }
        printf("RESULT: PASS - Test 4 (Zero channels / zero frames: returned NULL)\n");
    }
    else if (test_num == 5) {
        // Test 5: Unsupported sample sizes (e.g. 24-bit, 0-bit, 12-bit)
        short raw16[] = { 10, 20, 30, 40 };
        printf("Subtest 5a: sampleSize == 24\n");
        Wave w24 = { .data = raw16, .frameCount = 2, .sampleRate = 44100, .sampleSize = 24, .channels = 1 };
        float *s24 = LoadWaveSamples(w24);
        if (s24 != NULL) {
            printf("FAIL: Expected NULL for sampleSize = 24, got %p\n", (void*)s24);
            UnloadWaveSamples(s24);
            return 1;
        }

        printf("Subtest 5b: sampleSize == 0\n");
        Wave w0 = { .data = raw16, .frameCount = 2, .sampleRate = 44100, .sampleSize = 0, .channels = 1 };
        float *s0 = LoadWaveSamples(w0);
        if (s0 != NULL) {
            printf("FAIL: Expected NULL for sampleSize = 0, got %p\n", (void*)s0);
            UnloadWaveSamples(s0);
            return 1;
        }

        printf("Subtest 5c: sampleSize == 12\n");
        Wave w12 = { .data = raw16, .frameCount = 2, .sampleRate = 44100, .sampleSize = 12, .channels = 1 };
        float *s12 = LoadWaveSamples(w12);
        if (s12 != NULL) {
            printf("FAIL: Expected NULL for sampleSize = 12, got %p\n", (void*)s12);
            UnloadWaveSamples(s12);
            return 1;
        }
        printf("RESULT: PASS - Test 5 (Unsupported sample size: returned NULL)\n");
    }
    else if (test_num == 6) {
        // Test 6: Overflowing sample count
        short raw16[] = { 100, 200 };
        Wave w = { .data = raw16, .frameCount = 0xFFFFFFFF, .sampleRate = 44100, .sampleSize = 16, .channels = 0xFFFFFFFF };
        printf("  Calling LoadWaveSamples with overflowing frameCount/channels...\n");
        float *s = LoadWaveSamples(w);
        if (s != NULL) {
            printf("FAIL: Expected NULL when sample count overflows, got %p\n", (void*)s);
            UnloadWaveSamples(s);
            return 1;
        }
        printf("RESULT: PASS - Test 6 (Overflowing sample count: returned NULL)\n");
    }

    return 0;
}
