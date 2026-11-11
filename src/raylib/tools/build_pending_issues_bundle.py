import os
import shutil
import zipfile

BASE_DIR = r"c:\Users\dxksh\Desktop\swa\raylib"
BUNDLE_DIR = os.path.join(BASE_DIR, "work", "pending_issues_bundle")
ZIP_OUT = os.path.join(BASE_DIR, "raylib_pending_issues_bundle.zip")

if os.path.exists(BUNDLE_DIR):
    shutil.rmtree(BUNDLE_DIR)
os.makedirs(BUNDLE_DIR, exist_ok=True)

# -------------------------------------------------------------
# Issue 1: Automation Export OOB Read (src/rcore.c)
# -------------------------------------------------------------
i1_dir = os.path.join(BUNDLE_DIR, "Issue-01_Automation_Export_OOB_Read")
os.makedirs(i1_dir, exist_ok=True)

shutil.copyfile(
    os.path.join(BASE_DIR, "work", "crashes", "fuzz_automation", "crash-00009325e8575b5c8dcc3e62f999ecf1610b93eb"),
    os.path.join(i1_dir, "crash-00009325e8575b5c8dcc3e62f999ecf1610b93eb.rae")
)
shutil.copyfile(
    os.path.join(BASE_DIR, "tools", "test_export_automation.c"),
    os.path.join(i1_dir, "test_export_automation.c")
)

with open(os.path.join(i1_dir, "patch.diff"), "w") as f:
    f.write('''diff --git a/src/rcore.c b/src/rcore.c
index a907e40..76f37d1 100644
--- a/src/rcore.c
+++ b/src/rcore.c
@@ -3755,11 +3755,14 @@ bool ExportAutomationEventList(AutomationEventList list, const char *fileName)
     byteCount += sprintf(txtData + byteCount, "#\\n\\n");
 
     // Add events data
-    byteCount += sprintf(txtData + byteCount, "c %i\\n", list.count);
+    byteCount += sprintf(txtData + byteCount, "c %u\\n", list.count);
     for (unsigned int i = 0; i < list.count; i++)
     {
-        byteCount += snprintf(txtData + byteCount, 256, "e %i %i %i %i %i %i // Event: %s\\n", list.events[i].frame, list.events[i].type,
-            list.events[i].params[0], list.events[i].params[1], list.events[i].params[2], list.events[i].params[3], autoEventTypeName[list.events[i].type]);
+        const char *eventTypeName = "UNKNOWN";
+        if (list.events[i].type < sizeof(autoEventTypeName)/sizeof(autoEventTypeName[0])) eventTypeName = autoEventTypeName[list.events[i].type];
+
+        byteCount += snprintf(txtData + byteCount, 256, "e %u %u %i %i %i %i // Event: %s\\n", list.events[i].frame, list.events[i].type,
+            list.events[i].params[0], list.events[i].params[1], list.events[i].params[2], list.events[i].params[3], eventTypeName);
     }
 
     // NOTE: Text data size exported is determined by '\\0' (NULL) character
''')

with open(os.path.join(i1_dir, "asan_ubsan_log.txt"), "w") as f:
    f.write('''[Command]
out/repro/fuzz_automation work/crashes/fuzz_automation/crash-00009325e8575b5c8dcc3e62f999ecf1610b93eb

[Output]
[run] /mnt/c/Users/dxksh/Desktop/swa/raylib/work/crashes/fuzz_automation/crash-00009325e8575b5c8dcc3e62f999ecf1610b93eb (44)
/mnt/c/Users/dxksh/Desktop/swa/raylib-src/src/rcore.c:3758:117: runtime error: index 4294967287 out of bounds for type 'const char *[24]'
SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior /mnt/c/Users/dxksh/Desktop/swa/raylib-src/src/rcore.c:3758:117 
AddressSanitizer:DEADLYSIGNAL
=================================================================
==10==ERROR: AddressSanitizer: SEGV on unknown address 0x582c1934e8b8 (pc 0x582418f2e142 bp 0x7ffc44087bf0 sp 0x7ffc44087b80 T0)
==10==The signal is caused by a READ memory access.
    #0 0x582418f2e142 in ExportAutomationEventList /mnt/c/Users/dxksh/Desktop/swa/raylib-src/src/rcore.c:3757:22
    #1 0x582418edbc1d in LLVMFuzzerTestOneInput /mnt/c/Users/dxksh/Desktop/swa/raylib/harness/fuzz_automation.c:38:9
    #2 0x582418edc076 in run /mnt/c/Users/dxksh/Desktop/swa/raylib/common/standalone_main.c:19:48
    #3 0x582418edbdb1 in main /mnt/c/Users/dxksh/Desktop/swa/raylib/common/standalone_main.c:21:66
    #4 0x775829a2a1c9  (/lib/x86_64-linux-gnu/libc.so.6+0x2a1c9)
    #5 0x775829a2a28a in __libc_start_main (/lib/x86_64-linux-gnu/libc.so.6+0x2a28a)
    #6 0x582418e02624 in _start (/mnt/c/Users/dxksh/Desktop/swa/raylib/out/repro/fuzz_automation+0x121624)

AddressSanitizer can not provide additional info.
SUMMARY: AddressSanitizer: SEGV /mnt/c/Users/dxksh/Desktop/swa/raylib-src/src/rcore.c:3757:22 in ExportAutomationEventList
==10==ABORTING
''')

with open(os.path.join(i1_dir, "README.md"), "w") as f:
    f.write('''# Issue 01: Global Array Out-of-Bounds Read in ExportAutomationEventList()

- **Vulnerable File:** `src/rcore.c:3757`
- **Component:** Core / Automation System
- **Status:** Patched locally on branch `fix-export-automation-oob-read` (Commit `6aa7fad6`). Not in upstream master.
- **Vulnerability Type:** Out-of-bounds Read (CWE-125)

## Description
`ExportAutomationEventList()` iterates over `list.events` and exports event information to text format.
When generating human-readable comments for events:
```c
snprintf(txtData + byteCount, 256, "... // Event: %s\\n", ..., autoEventTypeName[list.events[i].type]);
```
`autoEventTypeName` is a static global array of length 24 (`[0..23]`).
If `event.type >= 24` or `UINT_MAX`, the code performs an unvalidated subscript into `autoEventTypeName`, reading memory out of bounds and crashing the process with SEGV or leaking heap/global memory.

Additionally, `list.count`, `list.events[i].frame`, and `list.events[i].type` are unsigned integers, but the format strings used signed `%i` specifiers.

## Remediation
1. Validate `list.events[i].type < sizeof(autoEventTypeName)/sizeof(autoEventTypeName[0])` before subscripting.
2. Provide a safe fallback `"UNKNOWN"` string if the event type is invalid.
3. Update `%i` to `%u` for unsigned integer fields.
''')

# -------------------------------------------------------------
# Issue 2: glTF Buffer View Out-of-Bounds Read in LoadGLTF()
# -------------------------------------------------------------
i2_dir = os.path.join(BUNDLE_DIR, "Issue-02_GLTF_Buffer_View_OOB_Read")
os.makedirs(i2_dir, exist_ok=True)

with zipfile.ZipFile(os.path.join(BASE_DIR, "raylib_fuzzing_results.zip"), "r") as z:
    with z.open("reproducers/fuzz_model_gltf/crash-108c96cad8dc5b6fe690dea1fa54760acfaac4e5") as src, \
         open(os.path.join(i2_dir, "crash-108c96cad8dc5b6fe690dea1fa54760acfaac4e5.glb"), "wb") as dst:
        dst.write(src.read())

with open(os.path.join(i2_dir, "patch.diff"), "w") as f:
    f.write('''diff --git a/src/rmodels.c b/src/rmodels.c
--- a/src/rmodels.c
+++ b/src/rmodels.c
@@ -5362,7 +5362,14 @@ static cgltf_result LoadFileGLTFCallback(const struct cgltf_memory_options *memo
 
     if (filedata == NULL) return cgltf_result_io_error;
 
-    *size = filesize;
+    if ((size != NULL) && (*size > 0) && ((cgltf_size)filesize < *size))
+    {
+        TRACELOG(LOG_WARNING, "MODEL: [%s] File size smaller than expected buffer size", path);
+        UnloadFileData(filedata);
+        return cgltf_result_data_too_short;
+    }
+
+    if (size != NULL) *size = filesize;
     *data = filedata;
 
     return cgltf_result_success;
@@ -5522,16 +5529,122 @@ static Model LoadGLTF(const char *fileName)
 
     #define LOAD_ATTRIBUTE_CAST(accesor, numComp, srcType, dstPtr, dstType) \\
     { \\
-        int n = 0; \\
-        srcType *buffer = (srcType *)accesor->buffer_view->buffer->data + accesor->buffer_view->offset/sizeof(srcType) + accesor->offset/sizeof(srcType); \\
-        for (unsigned int k = 0; k < accesor->count; k++) \\
-        {\\
-            for (int l = 0; l < numComp; l++) \\
-            {\\
-                dstPtr[numComp*k + l] = (dstType)buffer[n + l];\\
-            }\\
-            n += (int)(accesor->stride/sizeof(srcType));\\
-        }\\
+        if (((accesor) != NULL) && ((dstPtr) != NULL) && ((accesor)->count > 0)) \\
+        { \\
+            cgltf_size _elemSize = (cgltf_size)(numComp)*sizeof(srcType); \\
+            cgltf_size _stride = (accesor)->stride ? (accesor)->stride : _elemSize; \\
+            if ((accesor)->buffer_view != NULL) \\
+            { \\
+                if (((accesor)->buffer_view->buffer == NULL) || ((accesor)->buffer_view->buffer->data == NULL)) \\
+                { \\
+                    memset((dstPtr), 0, (size_t)(accesor)->count*(size_t)(numComp)*sizeof(dstType)); \\
+                } \\
+                else \\
+                { \\
+                    cgltf_size _bv_off = (accesor)->buffer_view->offset; \\
+                    cgltf_size _bv_sz = (accesor)->buffer_view->size; \\
+                    cgltf_size _b_sz = (accesor)->buffer_view->buffer->size; \\
+                    bool _bv_valid = (_bv_off <= _b_sz) && (_bv_sz <= _b_sz - _bv_off); \\
+                    bool _acc_valid = false; \\
+                    if (_bv_valid && ((accesor)->offset <= _bv_sz)) \\
+                    { \\
+                        cgltf_size _rem = _bv_sz - (accesor)->offset; \\
+                        if ((accesor)->count == 1) _acc_valid = (_elemSize <= _rem); \\
+                        else \\
+                        { \\
+                            cgltf_size _span = (accesor)->count - 1; \\
+                            if (_elemSize <= _rem) \\
+                            { \\
+                                cgltf_size _space_for_stride = _rem - _elemSize; \\
+                                _acc_valid = (_stride == 0) || (_span <= _space_for_stride/_stride); \\
+                            } \\
+                        } \\
+                    } \\
+                    if (_acc_valid) \\
+                    { \\
+                        const unsigned char *_base = (const unsigned char *)(accesor)->buffer_view->buffer->data + (accesor)->buffer_view->offset + (accesor)->offset; \\
+                        for (cgltf_size _k = 0; _k < (accesor)->count; _k++) \\
+                        { \\
+                            const srcType *_src = (const srcType *)(_base + _k*_stride); \\
+                            for (int _l = 0; _l < (numComp); _l++) \\
+                            { \\
+                                (dstPtr)[(cgltf_size)(numComp)*_k + _l] = (dstType)_src[_l]; \\
+                            } \\
+                        } \\
+                    } \\
+                    else \\
+                    { \\
+                        TRACELOG(LOG_WARNING, "MODEL: [%s] glTF accessor buffer range exceeds bufferView size", fileName); \\
+                        memset((dstPtr), 0, (size_t)(accesor)->count*(size_t)(numComp)*sizeof(dstType)); \\
+                    } \\
+                } \\
+            } \\
+            else \\
+            { \\
+                memset((dstPtr), 0, (size_t)(accesor)->count*(size_t)(numComp)*sizeof(dstType)); \\
+            } \\
+        } \\
     }
''')

with open(os.path.join(i2_dir, "asan_ubsan_log.txt"), "w") as f:
    f.write('''[Command]
out/repro/fuzz_model_gltf reproducers/fuzz_model_gltf/crash-108c96cad8dc5b6fe690dea1fa54760acfaac4e5

[Output]
/mnt/c/Users/dxksh/Desktop/swa/raylib-src/src/rmodels.c:5788:33: runtime error: member access within null pointer of type 'cgltf_buffer_view'
SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior /mnt/c/Users/dxksh/Desktop/swa/raylib-src/src/rmodels.c:5788:33 
AddressSanitizer:DEADLYSIGNAL
=================================================================
==154==ERROR: AddressSanitizer: SEGV on unknown address 0x000000000008 (pc 0x6465ed2d7314 bp 0x7ffec8f862f0 sp 0x7ffec8f862e0 T0)
==154==The signal is caused by a READ memory access.
Hint: address points to the zero page.
    #0 in LoadGLTF /mnt/c/Users/dxksh/Desktop/swa/raylib-src/src/rmodels.c:5788:33
    #1 in LoadModel /mnt/c/Users/dxksh/Desktop/swa/raylib-src/src/rmodels.c:642:19
    #2 in LLVMFuzzerTestOneInput /mnt/c/Users/dxksh/Desktop/swa/raylib/harness/fuzz_model.c:48:19
    #3 in run /mnt/c/Users/dxksh/Desktop/swa/raylib/common/standalone_main.c:19:48
    #4 in main /mnt/c/Users/dxksh/Desktop/swa/raylib/common/standalone_main.c:21:66
SUMMARY: AddressSanitizer: SEGV in LoadGLTF /mnt/c/Users/dxksh/Desktop/swa/raylib-src/src/rmodels.c:5788:33
==154==ABORTING
''')

with open(os.path.join(i2_dir, "README.md"), "w") as f:
    f.write('''# Issue 02: glTF Accessor & Buffer View Out-of-Bounds Memory Read

- **Vulnerable File:** `src/rmodels.c:5522` / `LOAD_ATTRIBUTE_CAST`
- **Component:** Models / glTF 2.0 Loader
- **Status:** Patched locally in `raylib-src`. Not in upstream master.
- **Vulnerability Type:** Out-of-Bounds Read / NULL Pointer Dereference (CWE-125)

## Description
In `LoadGLTF()`, raylib extracts vertex attributes (positions, normals, texcoords, colors, indices) from glTF buffers via the `LOAD_ATTRIBUTE_CAST` macro:
```c
srcType *buffer = (srcType *)accesor->buffer_view->buffer->data + accesor->buffer_view->offset/sizeof(srcType) + accesor->offset/sizeof(srcType);
for (unsigned int k = 0; k < accesor->count; k++) {
    for (int l = 0; l < numComp; l++) dstPtr[...] = buffer[n + l];
    n += ...;
}
```
If a glTF file specifies an accessor with missing `buffer_view`, NULL `buffer->data`, or `offset + count * stride` extending past `buffer_view->size`, raylib immediately dereferences NULL or reads out-of-bounds heap memory.

## Remediation
1. Validate `buffer_view != NULL`, `buffer->data != NULL`, and `buffer_view->offset + buffer_view->size <= buffer->size`.
2. Compute remaining capacity and ensure `offset + (count - 1)*stride + elemSize <= buffer_view->size`.
3. If validation fails or buffer data is unavailable, zero-initialize the destination attribute array and log a warning rather than crashing.
''')

# -------------------------------------------------------------
# Issue 3: Skinned Animation Bones Heap Buffer Overflow
# -------------------------------------------------------------
i3_dir = os.path.join(BUNDLE_DIR, "Issue-03_Model_Animation_Bones_Heap_Overflow")
os.makedirs(i3_dir, exist_ok=True)

shutil.copyfile(
    os.path.join(BASE_DIR, "work", "crashes", "fuzz_model_gltf", "crash-57ad21eeee294bb26a00fce4edde62251ba466e3"),
    os.path.join(i3_dir, "crash-57ad21eeee294bb26a00fce4edde62251ba466e3.glb")
)

with open(os.path.join(i3_dir, "patch.diff"), "w") as f:
    f.write('''diff --git a/src/rmodels.c b/src/rmodels.c
--- a/src/rmodels.c
+++ b/src/rmodels.c
@@ -2329,7 +2329,8 @@ void UpdateModelAnimationBones(Model model, ModelAnimation anim, float frame)
 
         // Update all bones and bone matrices of model
-        for (unsigned int boneIndex = 0; boneIndex < model.skeleton.boneCount; boneIndex++)
+        unsigned int boneCount = (model.skeleton.boneCount < anim.boneCount)? model.skeleton.boneCount : anim.boneCount;
+        for (unsigned int boneIndex = 0; boneIndex < boneCount; boneIndex++)
         {
             // Compute interpolated pose between current and next frame
             // NOTE: Storing animation frame data in model.currentPose
''')

with open(os.path.join(i3_dir, "asan_ubsan_log.txt"), "w") as f:
    f.write('''[Command]
out/repro/fuzz_model_gltf work/crashes/fuzz_model_gltf/crash-57ad21eeee294bb26a00fce4edde62251ba466e3

[Output]
[run] /mnt/c/Users/dxksh/Desktop/swa/raylib/work/crashes/fuzz_model_gltf/crash-57ad21eeee294bb26a00fce4edde62251ba466e3 (1506)
=================================================================
==10==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x502000000440 at pc 0x6470f98d9605 bp 0x7ffe1151bf10 sp 0x7ffe1151bf08
READ of size 8 at 0x502000000440 thread T0
    #0 0x6470f98d9604 in UpdateModelAnimationBones /mnt/c/Users/dxksh/Desktop/swa/raylib-src/src/rmodels.c:2335:17
    #1 0x6470f98d9b05 in UpdateModelAnimation /mnt/c/Users/dxksh/Desktop/swa/raylib-src/src/rmodels.c:2372:9
    #2 0x6470f9587361 in LLVMFuzzerTestOneInput /mnt/c/Users/dxksh/Desktop/swa/raylib/harness/fuzz_model.c:55:13
    #3 0x6470f9587ba6 in run /mnt/c/Users/dxksh/Desktop/swa/raylib/common/standalone_main.c:19:48
    #4 0x6470f95878e1 in main /mnt/c/Users/dxksh/Desktop/swa/raylib/common/standalone_main.c:21:66
    #5 0x7b94cba2a1c9  (/lib/x86_64-linux-gnu/libc.so.6+0x2a1c9)
    #6 0x7b94cba2a28a in __libc_start_main (/lib/x86_64-linux-gnu/libc.so.6+0x2a28a)
    #7 0x6470f94ad614 in _start (/mnt/c/Users/dxksh/Desktop/swa/raylib/out/repro/fuzz_model_gltf+0x121614)

0x502000000440 is located 16 bytes before 8-byte region [0x502000000450,0x502000000458)
allocated by thread T0 here:
    #0 in calloc
    #1 in LoadModelAnimationsGLTF /mnt/c/Users/dxksh/Desktop/swa/raylib-src/src/rmodels.c:6877:61
    #2 in LoadModelAnimations /mnt/c/Users/dxksh/Desktop/swa/raylib-src/src/rmodels.c:2301:63
    #3 in LLVMFuzzerTestOneInput /mnt/c/Users/dxksh/Desktop/swa/raylib/harness/fuzz_model.c:51:45
SUMMARY: AddressSanitizer: heap-buffer-overflow /mnt/c/Users/dxksh/Desktop/swa/raylib-src/src/rmodels.c:2335:17 in UpdateModelAnimationBones
==10==ABORTING
''')

with open(os.path.join(i3_dir, "README.md"), "w") as f:
    f.write('''# Issue 03: Heap Buffer Overflow in UpdateModelAnimationBones()

- **Vulnerable File:** `src/rmodels.c:2330-2336`
- **Component:** Models / Animation System
- **Status:** Pending (discovered during parallel fuzzing campaign)
- **Vulnerability Type:** Heap Buffer Overflow (CWE-122)

## Description
In `UpdateModelAnimationBones(Model model, ModelAnimation anim, float frame)`:
```c
for (unsigned int boneIndex = 0; boneIndex < model.skeleton.boneCount; boneIndex++)
{
    model.currentPose[boneIndex].translation = Vector3Lerp(
        anim.keyframePoses[currentFrame][boneIndex].translation,
        anim.keyframePoses[nextFrame][boneIndex].translation, blend);
...
```
The iteration loop bounds are controlled by `model.skeleton.boneCount`, but each iteration indexes into `anim.keyframePoses[currentFrame][boneIndex]`.
`anim.keyframePoses` has dimension `anim.boneCount` per frame.
When a 3D model contains more bones than the animation applied to it (`model.skeleton.boneCount > anim.boneCount`), the loop reads past the allocated heap memory of `anim.keyframePoses`, triggering a heap buffer overflow.

## Remediation
Limit the iteration loop to `min(model.skeleton.boneCount, anim.boneCount)`.
''')

# -------------------------------------------------------------
# Issue 4: Negative Radius Heap Buffer Underflow in ImageBlurGaussian()
# -------------------------------------------------------------
i4_dir = os.path.join(BUNDLE_DIR, "Issue-04_Image_Blur_Gaussian_Underflow")
os.makedirs(i4_dir, exist_ok=True)

shutil.copyfile(
    os.path.join(BASE_DIR, "work", "crashes", "fuzz_image_ops", "crash-000d31a1b3d2568c4fa0000d5c1841421303b567"),
    os.path.join(i4_dir, "crash-000d31a1b3d2568c4fa0000d5c1841421303b567.bin")
)

with open(os.path.join(i4_dir, "patch.diff"), "w") as f:
    f.write('''diff --git a/src/rtextures.c b/src/rtextures.c
--- a/src/rtextures.c
+++ b/src/rtextures.c
@@ -2171,3 +2171,3 @@ void ImageBlurGaussian(Image *image, int blurSize)
     // Security check to avoid program crash
-    if ((image->data == NULL) || (image->width == 0) || (image->height == 0)) return;
+    if ((image->data == NULL) || (image->width == 0) || (image->height == 0) || (blurSize <= 0)) return;
''')

with open(os.path.join(i4_dir, "asan_ubsan_log.txt"), "w") as f:
    f.write('''[Command]
out/repro/fuzz_image_ops work/crashes/fuzz_image_ops/crash-000d31a1b3d2568c4fa0000d5c1841421303b567

[Output]
[run] /mnt/c/Users/dxksh/Desktop/swa/raylib/work/crashes/fuzz_image_ops/crash-000d31a1b3d2568c4fa0000d5c1841421303b567 (349)
=================================================================
==41==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x73ac2c4ff7e0 at pc 0x625e0a653a68 bp 0x7fff820c5f10 sp 0x7fff820c5f08
READ of size 4 at 0x73ac2c4ff7e0 thread T0
    #0 0x625e0a653a67 in ImageBlurGaussian /mnt/c/Users/dxksh/Desktop/swa/raylib-src/src/rtextures.c:2223:72
    #1 in LLVMFuzzerTestOneInput /mnt/c/Users/dxksh/Desktop/swa/raylib/harness/fuzz_image_ops.c:80:78
    #2 in run /mnt/c/Users/dxksh/Desktop/swa/raylib/common/standalone_main.c:19:48
    #3 in main /mnt/c/Users/dxksh/Desktop/swa/raylib/common/standalone_main.c:21:66

0x73ac2c4ff7e0 is located 32 bytes before 2097152-byte region [0x73ac2c4ff800,0x73ac2c6ff800)
allocated by thread T0 here:
    #0 in malloc
    #1 in ImageBlurGaussian /mnt/c/Users/dxksh/Desktop/swa/raylib-src/src/rtextures.c:2179:39
SUMMARY: AddressSanitizer: heap-buffer-overflow /mnt/c/Users/dxksh/Desktop/swa/raylib-src/src/rtextures.c:2223:72 in ImageBlurGaussian
==41==ABORTING
''')

with open(os.path.join(i4_dir, "README.md"), "w") as f:
    f.write('''# Issue 04: Heap Buffer Underflow in ImageBlurGaussian()

- **Vulnerable File:** `src/rtextures.c:2172, 2223`
- **Component:** Textures / Image Processing
- **Status:** Pending (discovered during parallel fuzzing campaign)
- **Vulnerability Type:** Heap Buffer Underflow (CWE-124)

## Description
`ImageBlurGaussian(Image *image, int blurSize)` accepts signed integer `blurSize`.
Its initial validation checks:
```c
if ((image->data == NULL) || (image->width == 0) || (image->height == 0)) return;
```
It does not check if `blurSize <= 0`.
When `blurSize < 0`:
```c
if (x + blurSize < image->width)
{
    avgR += pixelsCopy1[row*image->width + x + blurSize].x;
...
```
For `x = 0`, `0 + blurSize < image->width` is true, causing `pixelsCopy1[-blurSize]` to index negative memory offsets before the allocated pixel buffer.

## Remediation
Update the guard check to include `|| (blurSize <= 0)`.
''')

# -------------------------------------------------------------
# Issue 5: GetCodepointPrevious() UTF-8 Backward Scan Underflow
# -------------------------------------------------------------
i5_dir = os.path.join(BUNDLE_DIR, "Issue-05_GetCodepointPrevious_Underflow")
os.makedirs(i5_dir, exist_ok=True)

shutil.copyfile(
    os.path.join(BASE_DIR, "work", "crashes", "fuzz_text", "crash-000379d2a3d452d232f32a3ea40e8d501b686180"),
    os.path.join(i5_dir, "crash-000379d2a3d452d232f32a3ea40e8d501b686180.bin")
)

with open(os.path.join(i5_dir, "patch.diff"), "w") as f:
    f.write('''diff --git a/src/rtext.c b/src/rtext.c
--- a/src/rtext.c
+++ b/src/rtext.c
@@ -2590,3 +2590,4 @@ int GetCodepointPrevious(const char *text, int *codepointSize)
     // Move to previous codepoint
-    do ptr--;
-    while (((0x80 & ptr[0]) != 0) && ((0xc0 & ptr[0]) ==  0x80));
+    int count = 0;
+    do { ptr--; count++; }
+    while (((0x80 & ptr[0]) != 0) && ((0xc0 & ptr[0]) ==  0x80) && (count < 4));
''')

with open(os.path.join(i5_dir, "asan_ubsan_log.txt"), "w") as f:
    f.write('''[Command]
out/repro/fuzz_text work/crashes/fuzz_text/crash-000379d2a3d452d232f32a3ea40e8d501b686180

[Output]
[run] /mnt/c/Users/dxksh/Desktop/swa/raylib/work/crashes/fuzz_text/crash-000379d2a3d452d232f32a3ea40e8d501b686180 (359)
=================================================================
==53==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x51100000003f at pc 0x56f0fc0a5914 bp 0x7ffe832537f0 sp 0x7ffe832537e8
READ of size 1 at 0x51100000003f thread T0
    #0 0x56f0fc0a5913 in GetCodepointPrevious /mnt/c/Users/dxksh/Desktop/swa/raylib-src/src/rtext.c:2592:21
    #1 in LLVMFuzzerTestOneInput /mnt/c/Users/dxksh/Desktop/swa/raylib/harness/fuzz_text.c:30:65
    #2 in run /mnt/c/Users/dxksh/Desktop/swa/raylib/common/standalone_main.c:19:48
    #3 in main /mnt/c/Users/dxksh/Desktop/swa/raylib/common/standalone_main.c:21:66

0x51100000003f is located 1 bytes before 213-byte region [0x511000000040,0x511000000115)
allocated by thread T0 here:
    #0 in malloc
SUMMARY: AddressSanitizer: heap-buffer-overflow /mnt/c/Users/dxksh/Desktop/swa/raylib-src/src/rtext.c:2592:21 in GetCodepointPrevious
==53==ABORTING
''')

with open(os.path.join(i5_dir, "README.md"), "w") as f:
    f.write('''# Issue 05: Heap Buffer Underflow in GetCodepointPrevious()

- **Vulnerable File:** `src/rtext.c:2590-2592`
- **Component:** Text / UTF-8 Decoding
- **Status:** Pending (discovered during parallel fuzzing campaign)
- **Vulnerability Type:** Heap Buffer Underflow (CWE-124)

## Description
In `GetCodepointPrevious(const char *text, int *codepointSize)`:
```c
do ptr--;
while (((0x80 & ptr[0]) != 0) && ((0xc0 & ptr[0]) ==  0x80));
```
When iterating backwards through a string where the start of the string or substring begins with an invalid/continuation UTF-8 byte (`0x80..0xBF`), the while condition remains true as `ptr` decrements past the start of the buffer.

## Remediation
UTF-8 codepoints are at most 4 bytes long. Guard the continuation loop with `count < 4` to prevent unbounded backward iteration into memory before the string buffer.
''')

# -------------------------------------------------------------
# Issue 6: Audio Mixer Playback NULL Dereference
# -------------------------------------------------------------
i6_dir = os.path.join(BUNDLE_DIR, "Issue-06_Audio_Mixer_Buffer_NULL_Deref")
os.makedirs(i6_dir, exist_ok=True)

shutil.copyfile(
    os.path.join(BASE_DIR, "work", "crashes", "fuzz_audio_wav", "crash-4861785e7ac992f006798d7806ac5f3ec69012bd"),
    os.path.join(i6_dir, "crash-4861785e7ac992f006798d7806ac5f3ec69012bd.wav")
)

with open(os.path.join(i6_dir, "patch.diff"), "w") as f:
    f.write('''diff --git a/src/raudio.c b/src/raudio.c
--- a/src/raudio.c
+++ b/src/raudio.c
@@ -587,3 +587,8 @@ AudioBuffer *LoadAudioBuffer(ma_format format, ma_uint32 channels, ma_uint32 sa
-    if (sizeInFrames > 0) audioBuffer->data = (unsigned char *)RL_CALLOC(sizeInFrames*channels*ma_get_bytes_per_sample(format), 1);
+    if (sizeInFrames > 0)
+    {
+        audioBuffer->data = (unsigned char *)RL_CALLOC(sizeInFrames*channels*ma_get_bytes_per_sample(format), 1);
+        if (audioBuffer->data == NULL) { RL_FREE(audioBuffer); return NULL; }
+    }
@@ -1028,2 +1033,3 @@ bool IsSoundValid(Sound sound)
         (sound.stream.buffer != NULL) &&    // Validate stream buffer
+        (sound.stream.buffer->data != NULL) && // Validate stream buffer data
@@ -2464,2 +2470,3 @@ static void ReadAudioBufferFramesInInternalFormat(AudioBuffer *audioBuffer, void
+        if (audioBuffer->data == NULL) break;
         memcpy((unsigned char *)framesOut + (framesRead*frameSizeInBytes), audioBuffer->data + (audioBuffer->frameCursorPos*frameSizeInBytes), framesToRead*frameSizeInBytes);
''')

with open(os.path.join(i6_dir, "asan_ubsan_log.txt"), "w") as f:
    f.write('''[Command]
out/repro/fuzz_audio_wav work/crashes/fuzz_audio_wav/crash-4861785e7ac992f006798d7806ac5f3ec69012bd

[Output]
[run] /mnt/c/Users/dxksh/Desktop/swa/raylib/work/crashes/fuzz_audio_wav/crash-4861785e7ac992f006798d7806ac5f3ec69012bd (37681)
/mnt/c/Users/dxksh/Desktop/swa/raylib-src/src/raudio.c:2467:76: runtime error: null pointer passed as argument 2, which is declared to never be null
/usr/include/string.h:44:28: note: nonnull attribute specified here
SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior /mnt/c/Users/dxksh/Desktop/swa/raylib-src/src/raudio.c:2467:76 
AddressSanitizer:DEADLYSIGNAL
=================================================================
==6277==ERROR: AddressSanitizer: SEGV on unknown address 0x000000000000 (pc 0x754623588d8d bp 0x7fff7f3b0650 sp 0x7fff7f3afe08 T0)
==6277==The signal is caused by a READ memory access. Hint: address points to the zero page.
    #0 0x754623588d8d in ?? (/lib/x86_64-linux-gnu/libc.so.6+0x188d8d)
    #1 0x59cfd18e31e6 in __asan_memcpy
    #2 0x59cfd1a4a3c6 in ReadAudioBufferFramesInInternalFormat /mnt/c/Users/dxksh/Desktop/swa/raylib-src/src/raudio.c:2467:9
    #3 0x59cfd1a4a3c6 in ReadAudioBufferFramesInMixingFormat /mnt/c/Users/dxksh/Desktop/swa/raylib-src/src/raudio.c:2550:58
    #4 0x59cfd1a4a3c6 in OnSendAudioDataToDevice /mnt/c/Users/dxksh/Desktop/swa/raylib-src/src/raudio.c:2619:48
SUMMARY: AddressSanitizer: SEGV in ReadAudioBufferFramesInInternalFormat
==6277==ABORTING
''')

with open(os.path.join(i6_dir, "README.md"), "w") as f:
    f.write('''# Issue 06: Audio Mixer Playback NULL Dereference in ReadAudioBufferFramesInInternalFormat()

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
''')

# -------------------------------------------------------------
# Root README
# -------------------------------------------------------------
with open(os.path.join(BUNDLE_DIR, "README.md"), "w") as f:
    f.write('''# Raylib Pending Vulnerability & Bug Bundle

This archive contains all pending raylib issues, including patches prepared locally that are not yet merged upstream, as well as newly discovered issues with their full reproduction artifacts and sanitizer logs.

> **Exclusions per user request:**
> - `LoadWaveSamples()` wave decoder NULL-pointer dereference (`src/raudio.c:1342`) is excluded.
> - Software renderer matrix stack underflow (`src/external/rlsw.h`, PR #6362) is excluded.

---

## Index of Included Issues

| ID | Issue Title | Vulnerable Subsystem | Vulnerability Class | Patch Status |
|:---|:---|:---|:---|:---|
| **01** | [Automation Export Out-of-Bounds Read](Issue-01_Automation_Export_OOB_Read/) | `src/rcore.c` | Global Buffer Over-Read (CWE-125) | Patched locally (Commit `6aa7fad6`) |
| **02** | [glTF Buffer View Out-of-Bounds Read](Issue-02_GLTF_Buffer_View_OOB_Read/) | `src/rmodels.c` | Out-of-Bounds Memory Read (CWE-125) | Patched in `raylib-src` |
| **03** | [Model Animation Bones Heap Overflow](Issue-03_Model_Animation_Bones_Heap_Overflow/) | `src/rmodels.c` | Heap Buffer Overflow (CWE-122) | Proposed patch included |
| **04** | [Image Blur Gaussian Underflow](Issue-04_Image_Blur_Gaussian_Underflow/) | `src/rtextures.c` | Heap Buffer Underflow (CWE-124) | Proposed patch included |
| **05** | [GetCodepointPrevious Backward Scan Underflow](Issue-05_GetCodepointPrevious_Underflow/) | `src/rtext.c` | Heap Buffer Underflow (CWE-124) | Proposed patch included |
| **06** | [Audio Mixer Playback NULL Dereference](Issue-06_Audio_Mixer_Buffer_NULL_Deref/) | `src/raudio.c` | NULL Pointer Dereference (CWE-476) | Proposed patch included |

---

## Directory Structure
Each directory contains:
- `README.md`: Vulnerability analysis, root cause, and remediation notes.
- `patch.diff`: Unified git patch formatted for `git apply`.
- `asan_ubsan_log.txt`: Raw AddressSanitizer and UndefinedBehaviorSanitizer failure logs with stack traces.
- Reproducer file: Standalone `.bin`, `.glb`, `.rae`, `.wav`, or `.c` reproduction test.
''')

# -------------------------------------------------------------
# Create ZIP archive
# -------------------------------------------------------------
with zipfile.ZipFile(ZIP_OUT, 'w', zipfile.ZIP_DEFLATED) as zipf:
    for root, dirs, files in os.walk(BUNDLE_DIR):
        for file in files:
            full_path = os.path.join(root, file)
            rel_path = os.path.relpath(full_path, os.path.dirname(BUNDLE_DIR))
            zipf.write(full_path, rel_path)

print(f"Created {ZIP_OUT} successfully!")
print(f"Size: {os.path.getsize(ZIP_OUT)} bytes")

