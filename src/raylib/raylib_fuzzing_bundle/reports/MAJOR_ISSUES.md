# Summary of Major Issues Found in Raylib (Commit 3b12ba1)

### 1. Software Rasterizer Matrix Stack Underflow
- **File & Line:** `src/external/rlsw.h:4379` in `swPopMatrix()`
- **Severity:** Very High (Memory Corruption / SEGV)
- **Description:** When `RLSW.stackModelviewCounter == 1`, the guard check `1 <= 0` passes. Evaluating `(--counter) - 1` computes index `-1` (`0xFFFFFFFF`), pointing `RLSW.currentMatrix` outside the `stackModelview[8]` array. The subsequent draw call writes directly into invalid memory.
- **Fix:** Update guard to check `if (RLSW.stackModelviewCounter < 2)`.

---

### 2. Untrusted Automation Event Replay Out-of-Bounds Memory Write
- **File & Line:** `src/rcore.c:3850` in `PlayAutomationEvent()`
- **Severity:** Very High (Arbitrary Intra-Struct Heap Write)
- **Description:** Parameters from untrusted `.rae` files are used directly as array indices into `CORE.Input.Gamepad.axisState[event.params[0]][event.params[1]]` and button arrays without bounds checks.
- **Fix:** Verify `event.params[0] < MAX_GAMEPADS` and `event.params[1] < MAX_GAMEPAD_AXES`.

---

### 3. Automation Event Type Global Buffer Over-Read
- **File & Line:** `src/rcore.c:3758` in `autoEventTypeName()`
- **Severity:** Major (Information Disclosure / Over-read)
- **Description:** `autoEventTypeName` indexes into `autoEventTypeNames[24]` using unvalidated `event.type`.
- **Fix:** Bound-check `event.type < 24` before indexing.

---

### 4. glTF Missing Buffer View Validation
- **File & Line:** `src/rmodels.c:5788` in `LoadGLTF()`
- **Severity:** Major (NULL Pointer Dereference / Heap Over-read)
- **Description:** Iterates glTF accessors and loads buffer views without verifying non-NULL status or buffer bounds.
- **Fix:** Call `cgltf_validate()` on parsed data.

---

### 5. Audio Frame Allocation Failure NULL Pointer Dereference
- **File & Line:** `src/raudio.c:1330–1337` in `LoadWaveSamples()`
- **Severity:** Medium (Denial of Service Crash)
- **Description:** When `RL_MALLOC` returns NULL on large allocations or integer overflows, the returned pointer is immediately dereferenced in the sample unpacking loop.
- **Fix:** Check `if (samples == NULL) return NULL;`.

---

### 6. Font Atlas Generation Heap Over-Read on 0 Glyphs
- **File & Line:** `src/rtext.c:284` in `GenImageFontAtlas()`
- **Severity:** Medium (Heap Buffer Over-read)
- **Description:** When an input file resolves 0 glyphs, the atlas generator defaults `glyphCount` to 95 and iterates past the unallocated glyph buffer.
- **Fix:** Validate `glyphCount > 0` before packing.
