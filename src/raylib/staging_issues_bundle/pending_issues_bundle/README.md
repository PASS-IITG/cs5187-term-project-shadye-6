# raylib Pending Security Issues & Fuzzing Reproducers Bundle

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
