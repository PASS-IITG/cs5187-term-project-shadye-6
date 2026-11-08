/* Audio decoders: dr_wav, stb_vorbis, dr_mp3, qoa, dr_flac, jar_xm, jar_mod — via both the
 * one-shot Wave path and the streaming Music path, plus WaveFormat/Crop conversion, encoders
 * (ExportWave -> dr_wav/qoa writers) and the mixer.
 *
 * Determinism trick: raudio.c is #included so its static internals are reachable. The miniaudio
 * device (null backend) is initialised once and immediately STOPPED, so no audio thread runs;
 * the harness then pumps OnSendAudioDataToDevice() itself. Every decode/mix step happens on the
 * fuzzing thread, in input-determined order => reproducible crashes, no TSan noise.
 * Params: last 8 bytes (trailing junk is tolerated by all these containers/streams). */
#include "raudio.c"
#include "fuzz_common.h"
#include <stdlib.h>
#ifndef FMT
#define FMT ".wav"
#endif
FZ_USE_BINARY_MUTATOR

static float g_mix[2048 * 2];
static void pump(unsigned frames) { OnSendAudioDataToDevice(&AUDIO.System.device, g_mix, NULL, frames); }

int LLVMFuzzerTestOneInput(const uint8_t *d, size_t n) {
    static int audio_ok = -1;
    fz_init(0);
    if (audio_ok < 0) {
        InitAudioDevice(); audio_ok = IsAudioDeviceReady();
        if (audio_ok) ma_device_stop(&AUDIO.System.device);
    }
    if (n < 8 || n > (4u << 20)) return 0;
    fz_rd r = { d + n - 8, 8 };
    static const int rates[] = { 8000, 11025, 22050, 44100, 48000, 96000, 1, 192000 };   /* misuse adds INT_MAX below */
    /* WaveFormat contract is sampleSize {8,16,32}, channels {1,2}; FUZZ_API_MISUSE=1 adds 24-bit / 0 / 8 ch
     * (raylib doesn't validate them: miniaudio channel-converter overflow — API-misuse class, triage apart). */
    static const int sizes_ok[] = { 8, 16, 32, 16 }, chans_ok[] = { 1, 2, 2, 1 };
    static const int sizes_bad[] = { 8, 16, 32, 24 }, chans_bad[] = { 1, 2, 0, 8 };
    static int misuse = -1; if (misuse < 0) misuse = getenv("FUZZ_API_MISUSE") != NULL;
    const int *sizes = misuse ? sizes_bad : sizes_ok, *chans = misuse ? chans_bad : chans_ok;
    uint8_t p0 = fz_u8(&r), p1 = fz_u8(&r);
    int rate = (misuse && (p0 & 7) == 7) ? 0x7fffffff : rates[p0 & 7];

    /* ---- one-shot Wave ---- */
    Wave w = LoadWaveFromMemory(FMT, d, (int)n);
    if (IsWaveValid(w)) {
        size_t bytes = (size_t)w.frameCount * w.channels * (w.sampleSize / 8);
        if (bytes) { volatile unsigned char x = ((unsigned char *)w.data)[bytes - 1]; (void)x; }   /* header vs alloc */
        if (w.frameCount <= (1u << 21)) {
            Wave c = WaveCopy(w);
            WaveCrop(&c, fz_int_edge(&r, -4, (int)w.frameCount + 4), fz_int_edge(&r, -4, (int)w.frameCount + 4));
            WaveFormat(&c, rate, sizes[(p0 >> 3) & 3], chans[(p0 >> 5) & 3]);
            float *s = LoadWaveSamples(c); UnloadWaveSamples(s);
            static const char *ex[] = { ".wav", ".qoa", ".raw" };
            ExportWave(c, ex[p1 % 3]);
            if (audio_ok) { Sound snd = LoadSoundFromWave(c);
                if (IsSoundValid(snd)) { SetSoundPitch(snd, fz_float(&r, -2, 4)); SetSoundPan(snd, fz_float(&r, -1, 2));
                    PlaySound(snd); for (int i = 0; i < 4; i++) pump(1024); }
                UnloadSound(snd); }
            UnloadWave(c);
        }
    }
    UnloadWave(w);

    /* ---- streaming Music (decoder state machines, seek, loop) ---- */
    if (!audio_ok) return 0;
    Music m = LoadMusicStreamFromMemory(FMT, d, (int)n);
    if (IsMusicValid(m)) {
        float len = GetMusicTimeLength(m);
        PlayMusicStream(m);
        SetMusicPitch(m, (p1 & 0x80) ? fz_float(&r, -2, 8) : 1.0f);
        for (int i = 0; i < 48; i++) {
            UpdateMusicStream(m); pump(512 + (p1 & 0x3f) * 16);
            if (i == 16 || i == 32) SeekMusicStream(m, fz_float(&r, -1, len + 1));    /* NaN/Inf/neg included */
            if (!IsMusicStreamPlaying(m)) break;
        }
        (void)GetMusicTimePlayed(m);
        StopMusicStream(m);
    }
    UnloadMusicStream(m);
    return 0;
}
