# Structure-Aware Mutation Strategy & Invariant Catalog

This document details the mutation strategies implemented in `fuzz/custom_mutator.cpp` for targeting fastgltf v0.9.1.

---

## 1. Architectural Strategy

Ordinary byte-level mutators frequently mutate bytes randomly, destroying the enclosing container syntax (GLB header magic, chunk lengths, or JSON quotes/braces). In fastgltf, such inputs are rejected in the outermost parser layers (`determineGltfFileType`, `simdjson::dom::parser`), preventing coverage from reaching deep buffer indexing and accessor traversal logic.

To evaluate our central research question:
> *Under a constrained fuzzing budget, does structure-aware glTF/GLB mutation reach deeper fastgltf behavior and produce better findings than ordinary byte-level coverage-guided fuzzing?*

We implement a two-level mutation engine:
1. **GLB Structure Mutation**: Operates on the 12-byte container header and chunk layout.
2. **glTF Semantic Mutation**: Operates on JSON AST fields, cross-field invariants, and textual representations.

---

## 2. GLB Container Mutation Family

### Repaired Mode vs Unrepaired Mode
- **Repaired GLB Mode**:
  Recalculates chunk lengths and total GLB length to match the physical payload, and enforces glTF 2.0 4-byte alignment padding (0x20 for JSON, 0x00 for BIN). This guarantees that fastgltf accepts the container and enters deep parsing.
- **Unrepaired GLB Mode**:
  Intentionally leaves corrupt lengths, mismatched chunk bounds, and invalid chunk headers. This explores container error handling and bounds verification paths.

### Mutation Categories
1. **Header Fields**:
   - `magic`: 0x46546C67 ("glTF"), 0x00000000, 0xDEADBEEF, random byte flip.
   - `version`: 1, 2, 3, 0, 255.
   - `length`: $n-1$, $n+1$, 0, $\text{UINT32\_MAX}$, $\text{chunkLengths} + 8$.
2. **Chunk Manipulation**:
   - Chunk type corruption (e.g. invalid chunk types).
   - JSON chunk mutation (delegated to glTF semantic mutator).
   - BIN chunk mutation (truncation, padding corruption, extension).
   - Chunk reordering (swapping JSON and BIN chunks, duplicate chunks).

---

## 3. JSON Mutation Strategies

### Strategy A: DOM / AST Semantic Mutations
When input is valid JSON, parsed via `nlohmann::json`:
1. **Buffers**:
   - `byteLength`: set to boundary values relative to physical URI payload ($n-1, n, n+1, 0, \text{UINT32\_MAX}$).
   - `uri`: injected with data URI variations (`data:application/octet-stream;base64,...`) and malformed percent sequences (`%`, `%A`, `%00`).
2. **BufferViews**:
   - `byteOffset`: boundary values ($0, n-1, n+1$, buffer size $+ 1$).
   - `byteLength`: mismatched against underlying buffer.
   - `byteStride`: 0, 1, 2, 3, 4, 8, 12, 16, 252, 256, 1024.
   - `target`: 34962 (ARRAY_BUFFER), 34963 (ELEMENT_ARRAY_BUFFER), invalid constants.
3. **Accessors**:
   - `componentType`: 5120 (Byte), 5121 (UByte), 5122 (Short), 5123 (UShort), 5125 (UInt), 5126 (Float), 5130 (Double), 0, 9999.
   - `type`: SCALAR, VEC2, VEC3, VEC4, MAT2, MAT3, MAT4.
   - `count`: $0, 1, 2, 63, 64, 65, \text{UINT32\_MAX}$.
   - `byteOffset`: boundary arithmetic offsets.
4. **Sparse Accessors**:
   - `count`: mismatched against index / value bufferView sizes.
   - `indices` / `values`: pointing to non-existent bufferViews.
5. **Mesh Primitives**:
   - `attributes`: mapping attributes (e.g. POSITION) to incompatible accessor types.
   - `indices`: out-of-range accessor indices.

### Strategy B: Textual / Raw Mutations
When JSON DOM parsing fails, raw textual mutations are applied to retain simdjson-facing quirks:
- Extreme number representations: `1e99999`, `-0.0`, `NaN`, `Infinity`, `1e-99999`.
- Duplicate keys: duplicate `"asset"` or `"buffers"` objects.
- Truncated quotes and braces.
- Raw percent encodings inside URI strings.

---

## 4. Hybrid Mode Probability Distribution

In `FUZZ_MODE=hybrid`, mutations are sampled according to:
- **25%** Ordinary libFuzzer byte mutation (`LLVMFuzzerMutate`)
- **25%** Valid-preserving structure mutation (with repair)
- **40%** Invariant-breaking structure mutation (without repair)
- **10%** Procedural generator arm (`GltfGenerator`)

Envelope profile byte 0 is preserved with 90% probability, ensuring all 8 parser option configurations remain accessible throughout exploration.
