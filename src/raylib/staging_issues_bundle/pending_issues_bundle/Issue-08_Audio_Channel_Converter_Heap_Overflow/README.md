# Issue 08: Channel Converter Heap Buffer Overflow in LoadSoundFromWave()

- **Vulnerable File:** `src/raudio.c:972-975`, `src/external/miniaudio.h:55630`
- **Component:** Audio / Wave to Sound Loading and Channel Conversion
- **Status:** Pending
- **Vulnerability Type:** Heap Buffer Overflow (CWE-122)

## Description
When `LoadSoundFromWave()` converts an input wave format to the target audio device format (e.g., mono to stereo), it precomputes the required frame buffer size by passing `NULL` as the destination buffer to `ma_convert_frames()`.
Due to sub-frame rounding in miniaudio's resampling and mono-to-stereo conversion math, the actual frame count processed by `ma_channel_converter_process_pcm_frames__mono_in()` can write 1 frame beyond the estimated output count, overflowing `audioBuffer->data` by 4 bytes.

## Remediation
Allocate a small safety headroom (e.g. `frameCount + 4`) in `LoadAudioBuffer()` during format conversion in `LoadSoundFromWave()`.
