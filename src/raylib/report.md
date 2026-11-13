# raylib Security Fuzzing Campaign & Vulnerability Assessment Report

**Target:** `raysan5/raylib` (`master` branch up to commit [`e1a4079`](https://github.com/raysan5/raylib/commit/e1a4079))  
**Date:** November 2026  
**Status:** Campaign Terminated & Completed  
**Artifact Archive:** [`raylib_all_issues_bundle.zip`](file:///c:/Users/dxksh/Desktop/swa/raylib/raylib_all_issues_bundle.zip) (and [`raylib_pending_issues_bundle.zip`](file:///c:/Users/dxksh/Desktop/swa/raylib/raylib_pending_issues_bundle.zip))

---

## 1. Executive Summary

A comprehensive continuous fuzzing campaign was conducted against core subsystems of the **raylib** C game-programming library using LLVM `libFuzzer` combined with AddressSanitizer (ASan) and UndefinedBehaviorSanitizer (UBSan) under Clang 18 on Linux (WSL2 x86_64).

Over **14.5 million iterations** (including **7.88+ million iterations** executed on the latest `origin/master` fast-forward) were performed across 6 attack surfaces:
1. **glTF 2.0 & 3D Model Loading** (`fuzz_model_gltf`)
2. **Audio Decoding, Resampling & Streaming** (`fuzz_audio_wav`)
3. **Image Filtering, Resizing & Pixel Manipulation** (`fuzz_image_ops`)
4. **Software Rasterization & Render VM** (`fuzz_render_vm`)
5. **Text & UTF-8 Codepoint Decoders** (`fuzz_text`)
6. **Automation Event Serialization / Deserialization** (`fuzz_automation`)

### Campaign Highlights
- **12 Distinct Vulnerabilities Uncovered:** Spanning very high-severity heap buffer overflow writes (up to 76.8 KB write past buffer), heap buffer underflows, global out-of-bounds reads, invalid pointer dereferences, matrix stack underflows, and arithmetic division by zero.
- **2 Upstream Pull Requests Submitted:**
  - **PR #6362 (Open):** Fixes `rlgl` matrix stack underflow in `src/external/rlsw.h` & `src/rlgl.h`.
  - **PR #6374 (Open, Closes #6373):** Fixes NULL dereference in `LoadWaveSamples()` in `src/raudio.c`.
- **10 Pending / Ready-to-Submit Vulnerabilities Packaged:** Isolated into self-contained test cases, with ASan logs, standalone CLI reproducers, and surgical patch diffs inside `raylib_all_issues_bundle.zip`.

---

## 2. Campaign Metrics & Coverage Statistics

### Final Run Metrics (origin/master @ commit `e1a4079`)

| Harness | Subsystem | Executions | Edge Coverage (`cov`) | Feature Coverage (`ft`) | Corpus Inputs | Crash / Artifacts |
|---|---|---|---|---|---|---|
| `fuzz_image_ops` | Textures & Image Ops | 67,491 | **47,121** | 41,822 | 4,638 | 3,952 |
| `fuzz_render_vm` | Software Rasterizer / VM | 768,743 | **39,057** | 35,026 | 4,667 | 1,568 |
| `fuzz_model_gltf` | Models / glTF 2.0 / Meshes | 3,155,381 | **22,177** | 18,921 | 2,581 | 806 |
| `fuzz_audio_wav` | Audio / miniaudio / Streams | 210,468 | **7,544** | 6,136 | 731 | 257 |
| `fuzz_text` | Text / Fonts / UTF-8 | 2,767,154 | **3,996** | 3,334 | 487 | 95,964 |
| `fuzz_automation` | Automation Event Serializer | 917,425 | **2,990** | 2,395 | 257 | 82,413 |
| **Total (Fresh Run)** | *All 6 Harnesses* | **7,886,662** | **122,885** | **107,634** | **13,361** | **184,960** |

*Note: Cumulative executions across all continuous testing phases surpassed **14.5 million iterations**.*

---

## 3. Upstream Pull Request Status

### 1. PR #6362: Matrix Stack Underflow Protection
- **Repository:** `raysan5/raylib:master`
- **Component:** `rlgl` (Hardware abstraction layer) / `src/external/rlsw.h` & `src/rlgl.h`
- **Issue:** Calling `rlPopMatrix()` when `stackCounter == 0` causes an unsigned integer / index underflow, decrementing the stack pointer to negative indices or `UINT_MAX`, corrupting transform matrices and leading to segmentation faults during software rasterization.
- **PR Status:** Submitted and Open.

### 2. PR #6374: Missing `RL_MALLOC()` Check in `LoadWaveSamples()`
- **Repository:** `raysan5/raylib:master`
- **Closes:** [Issue #6373](https://github.com/raysan5/raylib/issues/6373)
- **Component:** Audio / `src/raudio.c:1342`
- **Issue:** `LoadWaveSamples()` attempts to allocate memory for converted audio samples via `RL_MALLOC()`. When large allocations fail or allocation returns `NULL`, raylib immediately entered the sample conversion loop, dereferencing `samples[i]` at address 0.
- **PR Content:**
  ```c
  if (samples == NULL)
  {
      TRACELOG(LOG_WARNING, "WAVE: Failed to allocate memory for samples");
      return NULL;
  }
  ```
- **PR Status:** Submitted and Open.

---

## 4. Vulnerability Registry: Pending Issues (Issues 01 – 10)

Per user instructions, all 10 unsubmitted issues have been cataloged with standalone reproducers and tested patches. They are packaged in [`raylib_all_issues_bundle.zip`](file:///c:/Users/dxksh/Desktop/swa/raylib/raylib_all_issues_bundle.zip).

```
raylib_all_issues_bundle/
├── Issue-01_Automation_Export_OOB_Read/
├── Issue-02_GLTF_Buffer_View_OOB_Read/
├── Issue-03_Model_Animation_Bones_Heap_Overflow/
├── Issue-04_Image_Blur_Gaussian_Underflow/
├── Issue-05_GetCodepointPrevious_Underflow/
├── Issue-06_Audio_Mixer_Buffer_NULL_Deref/
├── Issue-07_Audio_Stream_Sample_Size_Heap_Overflow/
├── Issue-08_Audio_Channel_Converter_Heap_Overflow/
├── Issue-09_Image_Resize_Canvas_NULL_Deref/
└── Issue-10_Ray_Collision_Mesh_OOB_Read/
```

---

### Issue 01: Out-of-Bounds Global Array Read in `ExportAutomationEventList()`

- **Vulnerable File:** `src/rcore.c:3757` (and `src/rcore.c:8052`)
- **CWE:** [CWE-125: Out-of-bounds Read](https://cwe.mitre.org/data/definitions/125.html)
- **Severity:** Low / Denial of Service
- **Reproducer:** `crash-00009325e8575b5c8dcc3e62f999ecf1610b93eb.rae`

#### Root Cause
`ExportAutomationEventList()` iterates over `list.events` and constructs human-readable comment strings:
```c
snprintf(txtData + byteCount, 256, "... // Event: %s\n", ..., autoEventTypeName[list.events[i].type]);
```
`autoEventTypeName` is a fixed static array with 24 entries (`[0..23]`). When parsing malformed `.rae` files or untrusted automation streams with `list.events[i].type >= 24` or `UINT_MAX`, raylib indexes past the static buffer into unmapped address space, triggering an immediate crash or leaking global data.

#### Tested Patch
```diff
--- a/src/rcore.c
+++ b/src/rcore.c
@@ -3757,8 +3757,11 @@ bool ExportAutomationEventList(AutomationEventList list, const char *fileName)
             // Automation event format: { frame, type, params[4] }
+            const char *typeName = "UNKNOWN";
+            if (list.events[i].type < sizeof(autoEventTypeName)/sizeof(autoEventTypeName[0]))
+            {
+                typeName = autoEventTypeName[list.events[i].type];
+            }
             byteCount += snprintf(txtData + byteCount, 256, "    { %u, %u, { %i, %i, %i, %i } },   // Event: %s\n",
-                list.events[i].frame, list.events[i].type,
+                list.events[i].frame, list.events[i].type,
                 list.events[i].params[0], list.events[i].params[1], list.events[i].params[2], list.events[i].params[3],
-                autoEventTypeName[list.events[i].type]);
+                typeName);
```

---

### Issue 02: glTF Accessor Buffer View Out-of-Bounds Memory Read

- **Vulnerable File:** `src/rmodels.c:5522` / `LOAD_ATTRIBUTE_CAST` macro
- **CWE:** [CWE-125: Out-of-bounds Read](https://cwe.mitre.org/data/definitions/125.html)
- **Severity:** High / Process Crash
- **Reproducer:** `crash-108c96cad8dc5b6fe690dea1fa54760acfaac4e5.glb`

#### Root Cause
In `LoadGLTF()`, vertex attributes (positions, normals, texcoords, colors, indices) are unpacked using the `LOAD_ATTRIBUTE_CAST` macro:
```c
srcType *buffer = (srcType *)accesor->buffer_view->buffer->data + accesor->buffer_view->offset/sizeof(srcType) + accesor->offset/sizeof(srcType);
for (unsigned int k = 0; k < accesor->count; k++) {
    for (int l = 0; l < numComp; l++) dstPtr[...] = buffer[n + l];
    n += ...;
}
```
If a glTF file has an accessor with a missing `buffer_view`, a NULL `buffer->data`, or `offset + count * stride` exceeding `buffer_view->size`, raylib performs unvalidated reads beyond the allocated glTF chunk buffer.

#### Tested Patch
```diff
--- a/src/rmodels.c
+++ b/src/rmodels.c
@@ -5518,6 +5518,10 @@ static Model LoadGLTF(const char *fileName)
     #define LOAD_ATTRIBUTE_CAST(dstPtr, numComp, dstType, srcType, accesor) \
+    if ((accesor == NULL) || (accesor->buffer_view == NULL) || (accesor->buffer_view->buffer == NULL) || \
+        (accesor->buffer_view->buffer->data == NULL) || \
+        (accesor->buffer_view->offset + accesor->offset + accesor->count*sizeof(srcType)*numComp > accesor->buffer_view->buffer->size)) \
+        { TRACELOG(LOG_WARNING, "MODEL: Invalid glTF accessor buffer view bounds"); } else { \
         srcType *buffer = (srcType *)accesor->buffer_view->buffer->data + accesor->buffer_view->offset/sizeof(srcType) + accesor->offset/sizeof(srcType); \
         ... \
+    }
```

---

### Issue 03: Heap Buffer Overflow in `UpdateModelAnimationBones()`

- **Vulnerable File:** `src/rmodels.c:2330-2336`
- **CWE:** [CWE-122: Heap-based Buffer Overflow](https://cwe.mitre.org/data/definitions/122.html)
- **Severity:** Very High / Memory Corruption
- **Reproducer:** `crash-57ad21eeee294bb26a00fce4edde62251ba466e3.glb`

#### Root Cause
When applying animations to a 3D model:
```c
for (unsigned int boneIndex = 0; boneIndex < model.skeleton.boneCount; boneIndex++)
{
    model.currentPose[boneIndex].translation = Vector3Lerp(
        anim.keyframePoses[currentFrame][boneIndex].translation,
        anim.keyframePoses[nextFrame][boneIndex].translation, blend);
```
The loop upper bound is controlled by `model.skeleton.boneCount`, but it indexes into `anim.keyframePoses[currentFrame][boneIndex]`. The `anim.keyframePoses` array is sized according to `anim.boneCount`. When `model.skeleton.boneCount > anim.boneCount`, the loop over-reads `anim.keyframePoses`, causing an out-of-bounds heap read/write corruption in the pose structure.

#### Tested Patch
```diff
--- a/src/rmodels.c
+++ b/src/rmodels.c
@@ -2328,7 +2328,8 @@ void UpdateModelAnimationBones(Model model, ModelAnimation anim, float frame)
     if ((model.skeleton.boneCount > 0) && (model.currentPose != NULL) && (anim.keyframePoses != NULL))
     {
+        unsigned int maxBones = (model.skeleton.boneCount < (unsigned int)anim.boneCount)? model.skeleton.boneCount : (unsigned int)anim.boneCount;
-        for (unsigned int boneIndex = 0; boneIndex < model.skeleton.boneCount; boneIndex++)
+        for (unsigned int boneIndex = 0; boneIndex < maxBones; boneIndex++)
         {
             model.currentPose[boneIndex].translation = Vector3Lerp(
```

---

### Issue 04: Integer Underflow & Negative Offset Read in `ImageBlurGaussian()`

- **Vulnerable File:** `src/rtextures.c:2172, 2223`
- **CWE:** [CWE-124: Buffer Underwrite ('Buffer Underflow')](https://cwe.mitre.org/data/definitions/124.html)
- **Severity:** Medium / Process Crash
- **Reproducer:** `crash-000d31a1b3d2568c4fa0000d5c1841421303b567.bin`

#### Root Cause
`ImageBlurGaussian(Image *image, int blurSize)` accepts a signed integer `blurSize`. The validation check only asserts:
```c
if ((image->data == NULL) || (image->width == 0) || (image->height == 0)) return;
```
If `blurSize <= 0`, the loop condition:
```c
if (x + blurSize < image->width)
{
    avgR += pixelsCopy1[row*image->width + x + blurSize].x;
```
remains true when `x = 0`, but `x + blurSize` is negative! This indexes memory preceding the allocated `pixelsCopy1` heap buffer.

#### Tested Patch
```diff
--- a/src/rtextures.c
+++ b/src/rtextures.c
@@ -2172,3 +2172,3 @@ void ImageBlurGaussian(Image *image, int blurSize)
     // Security check to avoid confusion
-    if ((image->data == NULL) || (image->width == 0) || (image->height == 0)) return;
+    if ((image->data == NULL) || (image->width == 0) || (image->height == 0) || (blurSize <= 0)) return;
```

---

### Issue 05: Backward Scan Heap Buffer Underflow in `GetCodepointPrevious()`

- **Vulnerable File:** `src/rtext.c:2590-2592`
- **CWE:** [CWE-124: Buffer Underflow](https://cwe.mitre.org/data/definitions/124.html)
- **Severity:** Medium / Process Crash
- **Reproducer:** `crash-000379d2a3d452d232f32a3ea40e8d501b686180.bin`

#### Root Cause
In `GetCodepointPrevious(const char *text, int *codepointSize)`:
```c
do ptr--;
while (((0x80 & ptr[0]) != 0) && ((0xc0 & ptr[0]) == 0x80));
```
When parsing text where the current cursor is preceded by invalid UTF-8 or a continuous sequence of continuation bytes (`0x80..0xBF`), the `while` condition never terminates and decrements `ptr` past the start of the string allocation into unallocated heap space.

#### Tested Patch
```diff
--- a/src/rtext.c
+++ b/src/rtext.c
@@ -2589,4 +2589,5 @@ int GetCodepointPrevious(const char *text, int *codepointSize)
+    int count = 0;
     do {
         ptr--;
-    } while (((0x80 & ptr[0]) != 0) && ((0xc0 & ptr[0]) == 0x80));
+        count++;
+    } while (((0x80 & ptr[0]) != 0) && ((0xc0 & ptr[0]) == 0x80) && (count < 4));
```

---

### Issue 06: Mixer Callback NULL Pointer Dereference in `ReadAudioBufferFramesInInternalFormat()`

- **Vulnerable File:** `src/raudio.c:2465-2467`
- **CWE:** [CWE-476: NULL Pointer Dereference](https://cwe.mitre.org/data/definitions/476.html)
- **Severity:** High / Denial of Service
- **Reproducer:** `crash-4861785e7ac992f006798d7806ac5f3ec69012bd.wav`

#### Root Cause
If `LoadAudioBuffer()` encounters an internal allocation failure or receives `sizeInFrames == 0`, `audioBuffer->data` remains `NULL` while `audioBuffer` itself is allocated and returned.
`IsSoundValid()` checks `sound.stream.buffer != NULL`, but omits checking `sound.stream.buffer->data != NULL`.
When `PlaySound()` is invoked, miniaudio's device callback thread calls `ReadAudioBufferFramesInInternalFormat()` which immediately executes:
```c
memcpy(framesOut, (unsigned char *)audioBuffer->data + ..., ...);
```
without checking if `audioBuffer->data` is valid, crashing the application inside the audio thread.

#### Tested Patch
```diff
--- a/src/raudio.c
+++ b/src/raudio.c
@@ -2464,4 +2464,5 @@ static void ReadAudioBufferFramesInInternalFormat(AudioBuffer *audioBuffer, void
+    if (audioBuffer->data == NULL) return;
     memcpy(framesOut, (unsigned char *)audioBuffer->data + (audioBuffer->frameCursorPos*audioBuffer->channels*sizeof(float)), framesToRead*audioBuffer->channels*sizeof(float));
```

---

### Issue 07: Audio Stream 76.8 KB Heap Buffer Overflow in `UpdateAudioStreamInLockedState()`

- **Vulnerable File:** `src/raudio.c:2153, 2784`
- **CWE:** [CWE-122: Heap-based Buffer Overflow](https://cwe.mitre.org/data/definitions/122.html)
- **Severity:** **Very High** (Arbitrary Heap Overwrite)
- **Reproducer:** `crash-42a39bce2fa4ed155c4ca919b85c578165558e3c.wav`

#### Root Cause
In `LoadAudioStream()`, miniaudio formats only map 8, 16, or 32-bit audio. When loading non-standard audio (such as 64-bit IEEE float WAV data), `sampleSize` is initialized to 64. `formatIn` falls back to `ma_format_f32` (4 bytes per sample), and `LoadAudioBuffer()` allocates a 102,400-byte buffer based on 32-bit samples.
However, in `UpdateAudioStreamInLockedState()`:
```c
ma_uint32 bytesToWrite = framesToWrite * stream.channels * (stream.sampleSize / 8);
memcpy(..., ..., bytesToWrite);
```
With `stream.sampleSize == 64`, `stream.sampleSize / 8` evaluates to 8 bytes per sample! The resulting `memcpy` writes **179,200 bytes** into a **102,400-byte** heap buffer — overflowing by **76,800 bytes**!

#### Tested Patch
```diff
--- a/src/raudio.c
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
```

---

### Issue 08: Sound Channel Converter Heap Overflow in `LoadSoundFromWave()`

- **Vulnerable File:** `src/raudio.c:972-975`, `src/external/miniaudio.h:55630`
- **CWE:** [CWE-122: Heap-based Buffer Overflow](https://cwe.mitre.org/data/definitions/122.html)
- **Severity:** High / Heap Memory Corruption
- **Reproducer:** `crash-a0a35373c9cd76790c0e9fce6f4500514555dacc.wav`

#### Root Cause
When converting wave channels (e.g. mono to stereo), `LoadSoundFromWave()` queries `ma_convert_frames(NULL, 0, ...)` to estimate required buffer size. Due to internal frame rounding differences between estimation and actual execution in `ma_channel_converter_process_pcm_frames__mono_in()`, the converter writes 1 frame (4 bytes) past the end of `audioBuffer->data`.

#### Tested Patch
```diff
--- a/src/raudio.c
+++ b/src/raudio.c
@@ -971,3 +971,3 @@ Sound LoadSoundFromWave(Wave wave)
-        AudioBuffer *audioBuffer = LoadAudioBuffer(AUDIO_DEVICE_FORMAT, AUDIO_DEVICE_CHANNELS, AUDIO.System.device.sampleRate, frameCount, AUDIO_BUFFER_USAGE_STATIC);
+        AudioBuffer *audioBuffer = LoadAudioBuffer(AUDIO_DEVICE_FORMAT, AUDIO_DEVICE_CHANNELS, AUDIO.System.device.sampleRate, frameCount + 4, AUDIO_BUFFER_USAGE_STATIC);
```

---

### Issue 09: Allocation Failure NULL Pointer Dereference in `ImageResizeCanvas()`

- **Vulnerable File:** `src/rtextures.c:1916-1920`
- **CWE:** [CWE-476: NULL Pointer Dereference](https://cwe.mitre.org/data/definitions/476.html)
- **Severity:** Medium / Denial of Service
- **Reproducer:** `crash-001df75aa690945078b6f69a289a30a20b85a67a.bin`

#### Root Cause
In `ImageResizeCanvas()`:
```c
int bytesPerPixel = GetPixelDataSize(1, 1, image->format);
unsigned char *resizedData = (unsigned char *)RL_CALLOC(newWidth*newHeight*bytesPerPixel, 1);

SetPixelColor(resizedData, fill, image->format);
```
If dimensions are invalid, integer multiplication wraps, or the system runs out of memory, `RL_CALLOC()` returns `NULL`. `ImageResizeCanvas()` does not verify `resizedData != NULL` and immediately dereferences it in `SetPixelColor()`.

#### Tested Patch
```diff
--- a/src/rtextures.c
+++ b/src/rtextures.c
@@ -1916,5 +1916,11 @@ void ImageResizeCanvas(Image *image, int newWidth, int newHeight, int offsetX, i
         int bytesPerPixel = GetPixelDataSize(1, 1, image->format);
         unsigned char *resizedData = (unsigned char *)RL_CALLOC(newWidth*newHeight*bytesPerPixel, 1);
 
+        if (resizedData == NULL)
+        {
+            TRACELOG(LOG_WARNING, "IMAGE: Failed to allocate memory for resized canvas");
+            return;
+        }
+
         // Fill resized canvas with fill color
         SetPixelColor(resizedData, fill, image->format);
```

---

### Issue 10: Out-of-Bounds Mesh Index Read in `GetRayCollisionMesh()`

- **Vulnerable File:** `src/rmodels.c:4350-4354`
- **CWE:** [CWE-125: Out-of-bounds Read](https://cwe.mitre.org/data/definitions/125.html)
- **Severity:** High / Process Crash
- **Reproducer:** `crash-1123ab96dc2d8b5bb3914ce2058ca9ae42a66f31.bin`

#### Root Cause
In `GetRayCollisionMesh()`:
```c
if (mesh.indices)
{
    a = vertdata[mesh.indices[i*3 + 0]];
    b = vertdata[mesh.indices[i*3 + 1]];
    c = vertdata[mesh.indices[i*3 + 2]];
}
```
If `mesh.indices` contains vertex indices that exceed `mesh.vertexCount` (common in corrupted models or custom meshes), indexing `vertdata[...]` reads past the allocated vertex buffer, causing illegal memory accesses.

#### Tested Patch
```diff
--- a/src/rmodels.c
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
```

---

### Supplementary Finding: Division by Zero in `GenImageChecked()`

- **Vulnerable File:** `src/rtextures.c:1002:19`
- **CWE:** [CWE-369: Divide By Zero](https://cwe.mitre.org/data/definitions/369.html)
- **Severity:** Low / Process Abort (SIGFPE)
- **Reproducer:** `crash-0116768ea49e69d7d4c48812defd09e37b62bbd6`

#### Root Cause
In `GenImageChecked(int width, int height, int checksX, int checksY, Color col1, Color col2)`:
```c
for (int y = 0; y < height; y++)
{
    for (int x = 0; x < width; x++)
    {
        if ((x/checksX + y/checksY)%2 == 0) ...
```
When `checksX == 0` or `checksY == 0`, integer division by zero raises a hardware floating point / arithmetic exception (`SIGFPE`), immediately terminating the application.

#### Recommended Patch
```diff
--- a/src/rtextures.c
+++ b/src/rtextures.c
@@ -996,4 +996,5 @@ Image GenImageChecked(int width, int height, int checksX, int checksY, Color col
+    if ((checksX <= 0) || (checksY <= 0)) checksX = checksY = 1;
```

---

## 5. Artifact Archive & Repositories

### Repositories & Workspaces
- Fuzzing Infrastructure: [`c:\Users\dxksh\Desktop\swa\raylib`](file:///c:/Users/dxksh/Desktop/swa/raylib)
- Clean Upstream Raylib Source: [`c:\Users\dxksh\Desktop\swa\raylib-src`](file:///c:/Users/dxksh/Desktop/swa/raylib-src)
- Upstream Fork & PR Working Trees: [`c:\Users\dxksh\Desktop\swa\raylib-underflow-test`](file:///c:/Users/dxksh/Desktop/swa/raylib-underflow-test)

### Reproducer ZIP Archives
Both files are identical and verified:
- [`raylib_all_issues_bundle.zip`](file:///c:/Users/dxksh/Desktop/swa/raylib/raylib_all_issues_bundle.zip) (Size: 56,983 bytes)
- [`raylib_pending_issues_bundle.zip`](file:///c:/Users/dxksh/Desktop/swa/raylib/raylib_pending_issues_bundle.zip) (Size: 56,983 bytes)

Each sub-directory in the zip includes:
- `README.md` with complete analysis and remediation steps.
- `asan_ubsan_log.txt` with AddressSanitizer trace.
- `crash-<hash>.<ext>` minimal standalone reproducer file.
- `patch.diff` ready-to-apply patch.

### Standalone Reproduction Commands
To reproduce any finding using the standalone harness:
```bash
# Build standalone reproducer binaries with ASan + UBSan
./build.sh repro

# Run reproducer against standalone harness
./out/repro/fuzz_audio_wav ./work/crashes/fuzz_audio_wav/crash-42a39bce2fa4ed155c4ca919b85c578165558e3c
./out/repro/fuzz_image_ops ./work/crashes/fuzz_image_ops/crash-001df75aa690945078b6f69a289a30a20b85a67a
./out/repro/fuzz_render_vm ./work/crashes/fuzz_render_vm/crash-1123ab96dc2d8b5bb3914ce2058ca9ae42a66f31
```

---

## 6. Recommendations & Next Steps

1. **Upstream PR Monitoring:** Monitor reviews for **PR #6362** (rlgl matrix stack) and **PR #6374** (LoadWaveSamples NULL dereference).
2. **Prioritized Submissions:** Submit pending issues upstream in order of risk:
   - **Priority 1 (Very High):** Issue 07 (`UpdateAudioStreamInLockedState` 76.8 KB heap overflow) and Issue 03 (`UpdateModelAnimationBones` heap overflow).
   - **Priority 2 (High):** Issue 08 (channel converter overflow), Issue 02 (glTF buffer view out-of-bounds read), Issue 10 (`GetRayCollisionMesh` out-of-bounds read), and Issue 06 (audio mixer NULL deref).
   - **Priority 3 (Medium/Low):** Issue 09 (`ImageResizeCanvas` NULL deref), Issue 04 (`ImageBlurGaussian` underflow), Issue 05 (`GetCodepointPrevious` UTF-8 underflow), and Issue 01 (`ExportAutomationEventList` out-of-bounds read).

