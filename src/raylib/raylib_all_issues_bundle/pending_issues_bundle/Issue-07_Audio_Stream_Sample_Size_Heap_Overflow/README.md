# Issue 07: Audio Stream Sample Size Heap Buffer Overflow in UpdateAudioStreamInLockedState()

- **Vulnerable File:** `src/raudio.c:2154, 2781-2784`
- **Component:** Audio / Streaming Audio Buffer Update
- **Status:** Pending
- **Vulnerability Type:** Heap Buffer Overflow (CWE-122)

## Description
When loading an audio stream or music stream from non-standard or 64-bit IEEE float WAV data, `sampleSize` is initialized to 64 (or values > 32).
In `LoadAudioStream()`, miniaudio formats only support 8, 16, or 32-bit audio; any other value defaults `formatIn` to `ma_format_f32` (4 bytes per sample), so `LoadAudioBuffer()` allocates memory based on 4 bytes per frame.
However, during streaming updates in `UpdateAudioStreamInLockedState()`, the copy length is computed as:
```c
ma_uint32 bytesToWrite = framesToWrite * stream.channels * (stream.sampleSize / 8);
```
With `stream.sampleSize == 64`, `stream.sampleSize / 8` evaluates to 8 bytes per sample, attempting to write 179,200 bytes into a 102,400-byte buffer (a 76,800-byte heap buffer overflow).

## Remediation
1. Validate `sampleSize` in `LoadAudioStream()`: reject sample sizes other than 8, 16, or 32 bits.
2. In `UpdateAudioStreamInLockedState()`, clamp `bytesToWrite` to the allocated subbuffer size.
