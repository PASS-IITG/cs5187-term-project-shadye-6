# Issue 06: Audio Mixer Playback NULL Dereference in ReadAudioBufferFramesInInternalFormat()

- **Vulnerable File:** `src/raudio.c:2465-2467`
- **Component:** Audio / Device Mixer Callback
- **Status:** Pending (discovered during parallel fuzzing campaign)
- **Vulnerability Type:** NULL Pointer Dereference (CWE-476)

## Description
When `LoadAudioBuffer()` encounters memory allocation failure or receives `sizeInFrames == 0`, `audioBuffer->data` is left NULL, but `audioBuffer` itself is returned.
`IsSoundValid()` verifies `sound.stream.buffer != NULL`, but does not verify `sound.stream.buffer->data != NULL`.
When playback starts via `PlaySound()`, miniaudio triggers the device callback `OnSendAudioDataToDevice()`, which invokes `ReadAudioBufferFramesInInternalFormat()`.
Line 2465 immediately calls:
```c
memcpy(..., audioBuffer->data + ..., ...);
```
without checking if `audioBuffer->data` is valid, triggering a fatal SEGV crash on address zero.

## Remediation
1. Verify `audioBuffer->data != NULL` in `LoadAudioBuffer()` when `sizeInFrames > 0`.
2. Add `(sound.stream.buffer->data != NULL)` to `IsSoundValid()`.
3. Add a defensive `if (audioBuffer->data == NULL) break;` in `ReadAudioBufferFramesInInternalFormat()`.
