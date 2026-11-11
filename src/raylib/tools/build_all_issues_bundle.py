import os
import shutil
import zipfile

BASE_DIR = r'c:\Users\dxksh\Desktop\swa\raylib'
STAGING = os.path.join(BASE_DIR, 'staging_issues_bundle', 'pending_issues_bundle')
os.makedirs(STAGING, exist_ok=True)

# -------------------------------------------------------------
# Issue 07: Audio Stream Sample Size Heap Buffer Overflow
# -------------------------------------------------------------
dir07 = os.path.join(STAGING, 'Issue-07_Audio_Stream_Sample_Size_Heap_Overflow')
os.makedirs(dir07, exist_ok=True)
repro07_src = os.path.join(BASE_DIR, 'work', 'crashes', 'fuzz_audio_wav', 'crash-42a39bce2fa4ed155c4ca919b85c578165558e3c')
shutil.copy2(repro07_src, os.path.join(dir07, 'crash-42a39bce2fa4ed155c4ca919b85c578165558e3c.wav'))

with open(os.path.join(dir07, 'asan_ubsan_log.txt'), 'w', encoding='utf-8') as f:
    f.write("""=================================================================
==10==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x533000019800 at pc 0x566b24d994f8 bp 0x7ffc6624c150 sp 0x7ffc6624b910
WRITE of size 76800 at 0x533000019800 thread T0
    #0 0x566b24d994f7 in __asan_memcpy (/mnt/c/Users/dxksh/Desktop/swa/raylib/out/repro/fuzz_audio_wav+0x20f4f7)
    #1 0x566b24f0fb96 in UpdateAudioStreamInLockedState /mnt/c/Users/dxksh/Desktop/swa/raylib-src/src/raudio.c:2784:17
    #2 0x566b24f0f371 in UpdateMusicStream /mnt/c/Users/dxksh/Desktop/swa/raylib-src/src/raudio.c:2071:9
    #3 0x566b24f128d4 in LLVMFuzzerTestOneInput /mnt/c/Users/dxksh/Desktop/swa/raylib/harness/fuzz_audio.c:69:13
    #4 0x566b24f80c96 in run /mnt/c/Users/dxksh/Desktop/swa/raylib/common/standalone_main.c:19:48
    #5 0x566b24f809d1 in main /mnt/c/Users/dxksh/Desktop/swa/raylib/common/standalone_main.c:21:66

0x533000019800 is located 0 bytes after 102400-byte region [0x533000000800,0x533000019800)
allocated by thread T0 here:
    #0 0x566b24d9b79d in calloc
    #1 0x566b24f01c67 in LoadAudioBuffer /mnt/c/Users/dxksh/Desktop/swa/raylib-src/src/raudio.c:587:64
    #2 0x566b24f0b4bd in LoadAudioStream /mnt/c/Users/dxksh/Desktop/swa/raylib-src/src/raudio.c:2171:21
    #3 0x566b24f0b4bd in LoadMusicStreamFromMemory /mnt/c/Users/dxksh/Desktop/swa/raylib-src/src/raudio.c:1586:28

SUMMARY: AddressSanitizer: heap-buffer-overflow in __asan_memcpy
""")

with open(os.path.join(dir07, 'patch.diff'), 'w', encoding='utf-8') as f:
    f.write("""--- a/src/raudio.c
+++ b/src/raudio.c
@@ -2153,6 +2153,12 @@ AudioStream LoadAudioStream(unsigned int sampleRate, unsigned int sampleSize, un
     stream.sampleSize = sampleSize;
     stream.channels = channels;

+    if ((sampleSize != 8) && (sampleSize != 16) && (sampleSize != 32))
+    {
+        TRACELOG(LOG_WARNING, "STREAM: Sample size %i bit not supported", sampleSize);
+        return stream;
+    }
+
     ma_format formatIn = ((stream.sampleSize == 8)? ma_format_u8 : ((stream.sampleSize == 16)? ma_format_s16 : ma_format_f32));

     // The size of a streaming buffer must be at least double the size of a period
""")

with open(os.path.join(dir07, 'README.md'), 'w', encoding='utf-8') as f:
    f.write("""# Issue 07: Audio Stream Sample Size Heap Buffer Overflow in UpdateAudioStreamInLockedState()

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
""")


# -------------------------------------------------------------
# Issue 08: Audio Channel Converter Heap Buffer Overflow
# -------------------------------------------------------------
dir08 = os.path.join(STAGING, 'Issue-08_Audio_Channel_Converter_Heap_Overflow')
os.makedirs(dir08, exist_ok=True)
repro08_src = os.path.join(BASE_DIR, 'work', 'crashes', 'fuzz_audio_wav', 'crash-a0a35373c9cd76790c0e9fce6f4500514555dacc')
shutil.copy2(repro08_src, os.path.join(dir08, 'crash-a0a35373c9cd76790c0e9fce6f4500514555dacc.wav'))

with open(os.path.join(dir08, 'asan_ubsan_log.txt'), 'w', encoding='utf-8') as f:
    f.write("""=================================================================
==10==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x7f1d57bda400 at pc 0x629ba41a72ec bp 0x7ffd41dd74b0 sp 0x7ffd41dd74a8
WRITE of size 4 at 0x7f1d57bda400 thread T0
    #0 0x629ba41a72eb in ma_channel_converter_process_pcm_frames__mono_in /mnt/c/Users/dxksh/Desktop/swa/raylib-src/src/external/miniaudio.h:55630:49
    #1 0x629ba41a72eb in ma_channel_converter_process_pcm_frames /mnt/c/Users/dxksh/Desktop/swa/raylib-src/src/external/miniaudio.h:55867:61
    #2 0x629ba41ab8c6 in ma_data_converter_process_pcm_frames__resample_first /mnt/c/Users/dxksh/Desktop/swa/raylib-src/src/external/miniaudio.h:56720:22
    #3 0x629ba41ab8c6 in ma_data_converter_process_pcm_frames /mnt/c/Users/dxksh/Desktop/swa/raylib-src/src/external/miniaudio.h:56929:70
    #4 0x629ba41b0761 in ma_convert_frames_ex /mnt/c/Users/dxksh/Desktop/swa/raylib-src/src/external/miniaudio.h:58084:18
    #5 0x629ba426e94e in ma_convert_frames /mnt/c/Users/dxksh/Desktop/swa/raylib-src/src/external/miniaudio.h:58046:12
    #6 0x629ba426e94e in LoadSoundFromWave /mnt/c/Users/dxksh/Desktop/swa/raylib-src/src/raudio.c:975:37

0x7f1d57bda400 is located 0 bytes after 220945408-byte region [0x7f1d4a924800,0x7f1d57bda400)
allocated by thread T0 here:
    #0 0x629ba410579d in calloc
    #1 0x629ba426bc67 in LoadAudioBuffer /mnt/c/Users/dxksh/Desktop/swa/raylib-src/src/raudio.c:587:64
    #2 0x629ba426e895 in LoadSoundFromWave /mnt/c/Users/dxksh/Desktop/swa/raylib-src/src/raudio.c:972:36

SUMMARY: AddressSanitizer: heap-buffer-overflow in ma_channel_converter_process_pcm_frames__mono_in
""")

with open(os.path.join(dir08, 'patch.diff'), 'w', encoding='utf-8') as f:
    f.write("""--- a/src/raudio.c
+++ b/src/raudio.c
@@ -968,8 +968,9 @@ Sound LoadSoundFromWave(Wave wave)
         ma_format formatIn = ((wave.sampleSize == 8)? ma_format_u8 : ((wave.sampleSize == 16)? ma_format_s16 : ma_format_f32));
         ma_uint32 frameCountIn = wave.frameCount;

+        // Add extra frames margin to prevent converter rounding differences from overflowing the buffer
         ma_uint32 frameCount = (ma_uint32)ma_convert_frames(NULL, 0, AUDIO_DEVICE_FORMAT, AUDIO_DEVICE_CHANNELS, AUDIO.System.device.sampleRate, NULL, frameCountIn, formatIn, wave.channels, wave.sampleRate);
         if (frameCount == 0) TRACELOG(LOG_WARNING, "SOUND: Failed to get frame count for format conversion");

-        AudioBuffer *audioBuffer = LoadAudioBuffer(AUDIO_DEVICE_FORMAT, AUDIO_DEVICE_CHANNELS, AUDIO.System.device.sampleRate, frameCount, AUDIO_BUFFER_USAGE_STATIC);
+        AudioBuffer *audioBuffer = LoadAudioBuffer(AUDIO_DEVICE_FORMAT, AUDIO_DEVICE_CHANNELS, AUDIO.System.device.sampleRate, frameCount + 4, AUDIO_BUFFER_USAGE_STATIC);
         if (audioBuffer != NULL)
         {
             frameCount = (ma_uint32)ma_convert_frames(audioBuffer->data, frameCount, AUDIO_DEVICE_FORMAT, AUDIO_DEVICE_CHANNELS, AUDIO.System.device.sampleRate, wave.data, frameCountIn, formatIn, wave.channels, wave.sampleRate);
""")

with open(os.path.join(dir08, 'README.md'), 'w', encoding='utf-8') as f:
    f.write("""# Issue 08: Channel Converter Heap Buffer Overflow in LoadSoundFromWave()

- **Vulnerable File:** `src/raudio.c:972-975`, `src/external/miniaudio.h:55630`
- **Component:** Audio / Wave to Sound Loading and Channel Conversion
- **Status:** Pending
- **Vulnerability Type:** Heap Buffer Overflow (CWE-122)

## Description
When `LoadSoundFromWave()` converts an input wave format to the target audio device format (e.g., mono to stereo), it precomputes the required frame buffer size by passing `NULL` as the destination buffer to `ma_convert_frames()`.
Due to sub-frame rounding in miniaudio's resampling and mono-to-stereo conversion math, the actual frame count processed by `ma_channel_converter_process_pcm_frames__mono_in()` can write 1 frame beyond the estimated output count, overflowing `audioBuffer->data` by 4 bytes.

## Remediation
Allocate a small safety headroom (e.g. `frameCount + 4`) in `LoadAudioBuffer()` during format conversion in `LoadSoundFromWave()`.
""")


# -------------------------------------------------------------
# Issue 09: Image Resize Canvas NULL Pointer Dereference
# -------------------------------------------------------------
dir09 = os.path.join(STAGING, 'Issue-09_Image_Resize_Canvas_NULL_Deref')
os.makedirs(dir09, exist_ok=True)
repro09_src = os.path.join(BASE_DIR, 'work', 'crashes', 'fuzz_image_ops', 'crash-001df75aa690945078b6f69a289a30a20b85a67a')
shutil.copy2(repro09_src, os.path.join(dir09, 'crash-001df75aa690945078b6f69a289a30a20b85a67a.bin'))

with open(os.path.join(dir09, 'asan_ubsan_log.txt'), 'w', encoding='utf-8') as f:
    f.write("""=================================================================
==10==ERROR: AddressSanitizer: SEGV on unknown address 0x000000000000 (pc 0x64740746c076 bp 0x7ffe8486dbc0 sp 0x7ffe8486db80 T0)
==10==The signal is caused by a WRITE memory access.
==10==Hint: address points to the zero page.
    #0 0x64740746c076 in SetPixelColor /mnt/c/Users/dxksh/Desktop/swa/raylib-src/src/rtextures.c:5710:42
    #1 0x64740746b3d5 in ImageResizeCanvas /mnt/c/Users/dxksh/Desktop/swa/raylib-src/src/rtextures.c:1920:9
    #2 0x647407342561 in LLVMFuzzerTestOneInput /mnt/c/Users/dxksh/Desktop/swa/raylib/harness/fuzz_image_ops.c:59:19
    #3 0x6474073477f6 in run /mnt/c/Users/dxksh/Desktop/swa/raylib/common/standalone_main.c:19:48
    #4 0x647407347531 in main /mnt/c/Users/dxksh/Desktop/swa/raylib/common/standalone_main.c:21:66

SUMMARY: AddressSanitizer: SEGV in SetPixelColor (src/rtextures.c:5710:42)
""")

with open(os.path.join(dir09, 'patch.diff'), 'w', encoding='utf-8') as f:
    f.write("""--- a/src/rtextures.c
+++ b/src/rtextures.c
@@ -1916,6 +1916,12 @@ void ImageResizeCanvas(Image *image, int newWidth, int newHeight, int offsetX, i
         int bytesPerPixel = GetPixelDataSize(1, 1, image->format);
         unsigned char *resizedData = (unsigned char *)RL_CALLOC(newWidth*newHeight*bytesPerPixel, 1);

+        if (resizedData == NULL)
+        {
+            TRACELOG(LOG_WARNING, "IMAGE: Failed to allocate memory for resized canvas");
+            return;
+        }
+
         // Fill resized canvas with fill color
         // Set first pixel with image->format
         SetPixelColor(resizedData, fill, image->format);
""")

with open(os.path.join(dir09, 'README.md'), 'w', encoding='utf-8') as f:
    f.write("""# Issue 09: ImageResizeCanvas() NULL Pointer Dereference on Allocation Failure

- **Vulnerable File:** `src/rtextures.c:1916-1920`
- **Component:** Textures / Image Canvas Resizing
- **Status:** Pending
- **Vulnerability Type:** NULL Pointer Dereference (CWE-476)

## Description
In `ImageResizeCanvas()`, memory for the resized image data is allocated via:
```c
unsigned char *resizedData = (unsigned char *)RL_CALLOC(newWidth*newHeight*bytesPerPixel, 1);
```
If dimensions are invalid, integer multiplication overflows, or the system runs low on memory, `RL_CALLOC()` returns `NULL`.
`ImageResizeCanvas()` does not verify whether `resizedData` is valid and immediately executes:
```c
SetPixelColor(resizedData, fill, image->format);
```
which dereferences `resizedData` as an address in the zero page, causing a fatal segmentation fault.

## Remediation
Check `if (resizedData == NULL)` immediately after the allocation and abort the operation with a warning log.
""")


# -------------------------------------------------------------
# Issue 10: Ray Collision Mesh Out-of-Bounds Read
# -------------------------------------------------------------
dir10 = os.path.join(STAGING, 'Issue-10_Ray_Collision_Mesh_OOB_Read')
os.makedirs(dir10, exist_ok=True)
repro10_src = os.path.join(BASE_DIR, 'work', 'crashes', 'fuzz_render_vm', 'crash-1123ab96dc2d8b5bb3914ce2058ca9ae42a66f31')
shutil.copy2(repro10_src, os.path.join(dir10, 'crash-1123ab96dc2d8b5bb3914ce2058ca9ae42a66f31.bin'))

with open(os.path.join(dir10, 'asan_ubsan_log.txt'), 'w', encoding='utf-8') as f:
    f.write("""=================================================================
==14==ERROR: AddressSanitizer: SEGV on unknown address 0x5020000c0084 (pc 0x588be91b868f bp 0x7ffd3aff99c0 sp 0x7ffd3aff9760 T0)
==14==The signal is caused by a READ memory access.
    #0 0x588be91b868f in GetRayCollisionMesh /mnt/c/Users/dxksh/Desktop/swa/raylib-src/src/rmodels.c:4352:21
    #1 0x588be8e2e7bc in LLVMFuzzerTestOneInput /mnt/c/Users/dxksh/Desktop/swa/raylib/harness/fuzz_render_vm.c:88:67
    #2 0x588be8e31866 in run /mnt/c/Users/dxksh/Desktop/swa/raylib/common/standalone_main.c:19:48
    #3 0x588be8e315a1 in main /mnt/c/Users/dxksh/Desktop/swa/raylib/common/standalone_main.c:21:66

SUMMARY: AddressSanitizer: SEGV in GetRayCollisionMesh (src/rmodels.c:4352:21)
""")

with open(os.path.join(dir10, 'patch.diff'), 'w', encoding='utf-8') as f:
    f.write("""--- a/src/rmodels.c
+++ b/src/rmodels.c
@@ -4349,6 +4349,12 @@ RayCollision GetRayCollisionMesh(Ray ray, Mesh mesh, Matrix transform)

             if (mesh.indices)
             {
+                unsigned short idx0 = mesh.indices[i*3 + 0];
+                unsigned short idx1 = mesh.indices[i*3 + 1];
+                unsigned short idx2 = mesh.indices[i*3 + 2];
+                if ((idx0 >= mesh.vertexCount) || (idx1 >= mesh.vertexCount) || (idx2 >= mesh.vertexCount)) continue;
+
                 a = vertdata[mesh.indices[i*3 + 0]];
                 b = vertdata[mesh.indices[i*3 + 1]];
                 c = vertdata[mesh.indices[i*3 + 2]];
""")

with open(os.path.join(dir10, 'README.md'), 'w', encoding='utf-8') as f:
    f.write("""# Issue 10: Out-of-Bounds Mesh Index Array Read in GetRayCollisionMesh()

- **Vulnerable File:** `src/rmodels.c:4350-4354`
- **Component:** Models / Ray-Mesh Collision Detection
- **Status:** Pending
- **Vulnerability Type:** Out-of-Bounds Read (CWE-125)

## Description
In `GetRayCollisionMesh()`, triangle collision test loops over all index triplets:
```c
if (mesh.indices)
{
    a = vertdata[mesh.indices[i*3 + 0]];
    b = vertdata[mesh.indices[i*3 + 1]];
    c = vertdata[mesh.indices[i*3 + 2]];
}
```
Indices in `mesh.indices` are 16-bit integers (`unsigned short`). If the mesh has fewer vertices than an index reference (`mesh.indices[i*3 + k] >= mesh.vertexCount`), reading `vertdata[...]` accesses out-of-bounds heap memory past the `mesh.vertices` allocation, causing an illegal read / segmentation fault.

## Remediation
Validate that each index in the triplet is strictly less than `mesh.vertexCount` before accessing `vertdata`.
""")


# -------------------------------------------------------------
# Top-Level Bundle README.md
# -------------------------------------------------------------
top_readme = """# raylib Pending Security Issues & Fuzzing Reproducers Bundle

This bundle contains all unsubmitted/pending security vulnerabilities, heap overflows, out-of-bounds reads, and integer underflows uncovered across the raylib fuzzing campaigns, complete with their minimal reproducer files, AddressSanitizer/UBSan crash traces, analysis, and recommended patches.

## Exclusions (Per Request)
The following issues have already been submitted upstream as GitHub Pull Requests and are **excluded** from this bundle:
1. **rlgl Matrix Stack Underflow** (`rlMatrixMode` / `rlPopMatrix` in `src/external/rlsw.h` & `src/rlgl.h`) &rarr; **Pull Request #6362** (Open on `raysan5/raylib:master`).
2. **Audio Wave NULL Dereference** (`LoadWaveSamples()` missing `RL_MALLOC()` check in `src/raudio.c`) &rarr; **Pull Request #6374** (Closes Issue #6373 on `raysan5/raylib:master`).

*(Note: Issue 06 below is a separate audio mixer buffer NULL dereference in `ReadAudioBufferFramesInInternalFormat()` device playback callback, which is unsubmitted).*

---

## Included Issues Index

| Issue Directory | Component | Vulnerability Type | Vulnerable File & Function | Severity |
|---|---|---|---|---|
| `Issue-01_Automation_Export_OOB_Read` | Core / Automation | Out-of-Bounds Heap Read | `src/rcore.c:8052` in `ExportAutomationEventList()` | Low / DoS |
| `Issue-02_GLTF_Buffer_View_OOB_Read` | Models / glTF | Out-of-Bounds Heap Read | `src/rmodels.c:4897` in `LoadGLTF()` | High / Crash |
| `Issue-03_Model_Animation_Bones_Heap_Overflow` | Models / Animations | Heap Buffer Overflow (OOB Write) | `src/rmodels.c:2335` in `UpdateModelAnimationBones()` | Critical |
| `Issue-04_Image_Blur_Gaussian_Underflow` | Textures / Image Ops | Heap Over-Read / Int Underflow | `src/rtextures.c:2204` in `ImageBlurGaussian()` | Medium / Crash |
| `Issue-05_GetCodepointPrevious_Underflow` | Text / UTF-8 | Heap Buffer Underflow | `src/rtext.c:2592` in `GetCodepointPrevious()` | Medium / Crash |
| `Issue-06_Audio_Mixer_Buffer_NULL_Deref` | Audio / Mixer Callback | NULL Pointer Dereference | `src/raudio.c:2465` in `ReadAudioBufferFramesInInternalFormat()` | High / Crash |
| `Issue-07_Audio_Stream_Sample_Size_Heap_Overflow` | Audio / Streams | Heap Buffer Overflow (76.8 KB Write) | `src/raudio.c:2784` in `UpdateAudioStreamInLockedState()` | Critical |
| `Issue-08_Audio_Channel_Converter_Heap_Overflow` | Audio / Sound Loader | Heap Buffer Overflow (4-Byte Write) | `src/raudio.c:975` in `LoadSoundFromWave()` | High / Crash |
| `Issue-09_Image_Resize_Canvas_NULL_Deref` | Textures / Canvas | NULL Pointer Dereference | `src/rtextures.c:1920` in `ImageResizeCanvas()` | Medium / Crash |
| `Issue-10_Ray_Collision_Mesh_OOB_Read` | Models / Collision | Out-of-Bounds Heap Read | `src/rmodels.c:4352` in `GetRayCollisionMesh()` | High / Crash |

---

## Directory Structure
Each issue directory is structured self-contained:
```
Issue-XX_Name/
├── README.md               # Detailed bug report, root cause analysis & remediation
├── asan_ubsan_log.txt      # Full AddressSanitizer / UndefinedBehaviorSanitizer crash log
├── crash-<hash>.<ext>      # Standalone reproducer artifact (WAV, GLB, RAE, BIN, etc.)
└── patch.diff              # Tested drop-in fix against raylib:master
```

---

## Verification
All reproducers and proposed patches were compiled with Clang 18 using AddressSanitizer and UndefinedBehaviorSanitizer:
```bash
./build.sh repro
./out/repro/<harness> <reproducer_file>
```
"""

with open(os.path.join(STAGING, 'README.md'), 'w', encoding='utf-8') as f:
    f.write(top_readme)

print('All 10 issue directories and top-level README generated successfully.')

# -------------------------------------------------------------
# Pack Zip Archives
# -------------------------------------------------------------
zip_dest1 = os.path.join(BASE_DIR, 'raylib_all_issues_bundle.zip')
zip_dest2 = os.path.join(BASE_DIR, 'raylib_pending_issues_bundle.zip')

for dest in [zip_dest1, zip_dest2]:
    with zipfile.ZipFile(dest, 'w', zipfile.ZIP_DEFLATED) as zf:
        for root, dirs, files in os.walk(STAGING):
            for file in files:
                full_path = os.path.join(root, file)
                rel_path = os.path.relpath(full_path, os.path.dirname(STAGING))
                zf.write(full_path, rel_path)
    print(f'Wrote {dest} ({os.path.getsize(dest)} bytes)')

