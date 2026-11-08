#define RAUDIO_STANDALONE
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <assert.h>

// Mock RL_MALLOC to simulate allocation failure
static bool g_force_malloc_fail = false;
static void *test_malloc(size_t sz) {
    if (g_force_malloc_fail) return NULL;
    return malloc(sz);
}
#define RL_MALLOC(sz) test_malloc(sz)
#define RL_FREE(p) free(p)

// Include raudio's LoadWaveSamples implementation
typedef struct Wave {
    unsigned int frameCount;
    unsigned int channels;
    unsigned int sampleRate;
    unsigned int sampleSize;
    void *data;
} Wave;

#define LOG_WARNING 0
static int g_tracelog_called = 0;
#define TRACELOG(level, ...) do { g_tracelog_called++; printf(__VA_ARGS__); printf("\n"); } while(0)

float *LoadWaveSamples(Wave wave)
{
    float *samples = (float *)RL_MALLOC(wave.frameCount*wave.channels*sizeof(float));

    if (samples == NULL)
    {
        TRACELOG(LOG_WARNING, "WAVE: Failed to allocate memory for samples");
        return NULL;
    }

    // NOTE: sampleCount is the total number of interlaced samples (including channels)

    for (unsigned int i = 0; i < wave.frameCount*wave.channels; i++)
    {
        if (wave.sampleSize == 8) samples[i] = (float)(((unsigned char *)wave.data)[i] - 128)/128.0f;
        else if (wave.sampleSize == 16) samples[i] = (float)(((short *)wave.data)[i])/32768.0f;
        else if (wave.sampleSize == 32) samples[i] = ((float *)wave.data)[i];
    }

    return samples;
}

int main(void) {
    printf("=== Test 1: Normal valid 16-bit Wave ===\n");
    short raw16[] = { 0, 16384, -16384, 32767 };
    Wave w1 = { .frameCount = 2, .channels = 2, .sampleRate = 44100, .sampleSize = 16, .data = raw16 };
    float *s1 = LoadWaveSamples(w1);
    assert(s1 != NULL);
    assert(s1[0] == 0.0f);
    assert(s1[1] > 0.49f && s1[1] < 0.51f);
    assert(s1[2] < -0.49f && s1[2] > -0.51f);
    free(s1);
    printf("PASS: Test 1\n\n");

    printf("=== Test 2: Normal valid 8-bit Wave ===\n");
    unsigned char raw8[] = { 128, 255, 0, 128 };
    Wave w2 = { .frameCount = 2, .channels = 2, .sampleRate = 44100, .sampleSize = 8, .data = raw8 };
    float *s2 = LoadWaveSamples(w2);
    assert(s2 != NULL);
    assert(s2[0] == 0.0f);
    assert(s2[2] == -1.0f);
    free(s2);
    printf("PASS: Test 2\n\n");

    printf("=== Test 3: Normal valid 32-bit float Wave ===\n");
    float raw32[] = { 0.25f, -0.75f };
    Wave w3 = { .frameCount = 1, .channels = 2, .sampleRate = 44100, .sampleSize = 32, .data = raw32 };
    float *s3 = LoadWaveSamples(w3);
    assert(s3 != NULL);
    assert(s3[0] == 0.25f);
    assert(s3[1] == -0.75f);
    free(s3);
    printf("PASS: Test 3\n\n");

    printf("=== Test 4: Simulated allocation failure (RL_MALLOC returns NULL) ===\n");
    g_force_malloc_fail = true;
    g_tracelog_called = 0;
    float *s4 = LoadWaveSamples(w1);
    assert(s4 == NULL);
    assert(g_tracelog_called == 1);
    printf("PASS: Test 4 returned NULL gracefully with TRACELOG warning\n\n");

    printf("=== ALL TESTS PASSED! ===\n");
    return 0;
}

