#define SUPPORT_FILEFORMAT_WAV 1
#include "raudio.c"
#include <stdio.h>

int main(int argc, char **argv) {
    if (argc < 2) return 1;
    InitAudioDevice();
    Wave w = LoadWave(argv[1]);
    printf("Loaded wave: frameCount=%u, channels=%u, sampleRate=%u, sampleSize=%u, data=%p\n",
           w.frameCount, w.channels, w.sampleRate, w.sampleSize, w.data);
    if (w.data != NULL) {
        Sound s = LoadSoundFromWave(w);
        printf("Sound: frameCount=%u, buffer=%p, data=%p\n",
               s.frameCount, s.stream.buffer, s.stream.buffer ? s.stream.buffer->data : NULL);
        UnloadSound(s);
    }
    UnloadWave(w);
    CloseAudioDevice();
    return 0;
}
