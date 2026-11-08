# fastgltf Fuzzer Architecture & System Design

## 1. System Overview

The `fastgltf-fuzzer` project evaluates the effectiveness of structure-aware mutation versus ordinary byte-level mutation against **fastgltf v0.9.1**. It combines LLVM libFuzzer with custom GLB parsing, JSON AST cross-field mutation, procedural generation, bounds-checking memory adapters, and a comprehensive evaluation suite.

```
                  +--------------------------------+
                  |          Seed Corpus           |
                  +--------------------------------+
                                   |
                                   v
                  +--------------------------------+
                  |          libFuzzer             |
                  +--------------------------------+
                                   |
         +-------------------------+-------------------------+
         |                                                   |
         v                                                   v
 [Ordinary Byte Mutation]                       [Structure-Aware Mutation]
                                                             |
                                      +----------------------+----------------------+
                                      |                      |                      |
                                      v                      v                      v
                                 [JSON AST]            [GLB Container]     [Procedural Generator]
                                      |                      |                      |
                                      +----------------------+----------------------+
                                                             |
                                                             v
                                                [Cross-Field Invariants]
                                                             |
                                                             v
                                               [Fuzzer Envelope Stream]
                                              [profile_byte][payload...]
                                                             |
                                                             v
                                                [GltfDataBuffer::FromBytes]
                                                             |
                                                             v
                                                  [fastgltf::Parser]
                                                             |
                                      +----------------------+----------------------+
                                      |                                             |
                                      v                                             v
                              [Parse Rejection]                               [Loaded Asset]
                                      |                                             |
                                      |                                             v
                                      |                                    [exerciseAsset]
                                      |                                  (Bounded Traversal)
                                      |                                             |
                                      |                           +-----------------+-----------------+
                                      |                           |                                   |
                                      |                           v                                   v
                                      |               [DefaultBufferAdapter]             [GuardedBufferAdapter]
                                      |                           |                       (ASan Redzone Alloc)
                                      |                           +-----------------+-----------------+
                                      |                                             |
                                      +---------------------------------------------+
                                                             |
                                                             v
                                             [ASan / UBSan / Invariant Check]
                                                             |
                                                             v
                                                  [Findings Management]
                                            (Triage, Minimization, Reports)
```

---

## 2. Key Architectural Components

### 1. Fuzzer Envelope (`fuzz/fuzz_common.hpp`)
Rather than maintaining separate binaries for each fastgltf configuration, input streams reserve byte 0 as a configuration profile selector:
$$\text{Input} = [\text{profile\_byte}][\text{glTF/GLB Payload Bytes}\dots]$$
Byte 0 maps deterministically to valid `fastgltf::Options` masks (None, AllowDouble, DecomposeNodeMatrices, GenerateMeshIndices, DontRequireValidAssetMember). The custom mutator preserves byte 0 with 90% probability to ensure all profiles remain continuously explored.

### 2. Guarded Buffer Data Adapter (`fuzz/guarded_buffer_adapter.hpp`)
In typical usage, `fastgltf::DefaultBufferDataAdapter` returns a `span` over a subregion of the parent buffer. If an out-of-bounds accessor access occurs, it may read adjacent valid data within the buffer without crashing.

`GuardedBufferDataAdapter` isolates each requested `bufferView` into an independent heap allocation (`std::vector<std::byte>` of exact declared size):
- Pre-checks source buffer bounds safely without out-of-bounds reads in the adapter.
- Returns a span pointing to the isolated allocation.
- In ASan builds, heap allocations are bordered by poisoned redzones. Any read past the declared `bufferView` extent immediately triggers an ASan `heap-buffer-overflow` report.

### 3. Bounded Asset Exerciser & Metamorphic Oracle (`fuzz/asset_exerciser.cpp`)
Exercises accessor tools while enforcing safety bounds:
- `MAX_ACCESSORS_EXERCISED = 100`
- `MAX_ELEMENTS_PER_ACCESSOR = 64`
- `MAX_OBJECTS_VISITED = 1000`
- **Metamorphic Oracle**: Verifies semantic equivalence between `getAccessorElement<T>`, `iterateAccessor<T>`, `iterateAccessorWithIndex<T>`, and `copyFromAccessor<T>` for sampled indices.

### 4. Independent Extent Calculation (`fuzz/reference_decoder.cpp`)
Performs independent checked arithmetic calculation of the byte range required by an accessor:
$$\text{Offset} = \text{byteOffset} + \text{stride} \times (\text{count} - 1) + \text{elementSize}$$
Verifies if `Offset > bufferView.byteLength` and records telemetry violations without suppressing target execution.

### 5. SanitizerCoverage Allowlisting (`cmake/coverage_allowlist.txt`)
Restricts Clang SanitizerCoverage instrumentation to:
- `src:*fastgltf*`
- `src:*simdjson*`
- `fun:*`
Prevents helper code, tests, and procedural generators from diluting coverage feedback.
