# Known Findings & Historical Issue Analysis

## Public Issue #144: Read Access Violation in `deserializeComponent`

### 1. Issue Overview
- **Issue Tracker Reference**: fastgltf public issue `#144`
- **Reported Affected Version**: v0.9.0
- **Reported Call Stack**:
  ```text
  iterateAccessorWithIndex -> deserializeComponent
  ```
- **Reported Symptom**: Read access violation / heap buffer overflow when reading component bytes beyond the allocated bufferView region.

---

### 2. Upstream Fix Analysis (Commit `ffebaa7`)

The fastgltf repository contains commit `ffebaa749b4ff7035e91c8b3c43adda491620ceb`:
> *Add bounds checks for accessors & bufferViews (see #144)*

```diff
diff --git a/src/fastgltf.cpp b/src/fastgltf.cpp
index d2927ca..83eac91 100644
--- a/src/fastgltf.cpp
+++ b/src/fastgltf.cpp
@@ -976,6 +976,14 @@ fg::Error fg::validate(const Asset& asset) {
 			}
 		}
 
+		if (accessor.bufferViewIndex.has_value()) {
+			const auto& bufferView = asset.bufferViews[accessor.bufferViewIndex.value()];
+			const auto stride = bufferView.byteStride.value_or(getElementByteSize(accessor.type, accessor.componentType));
+			if (accessor.byteOffset + stride * (accessor.count - 1) +
+				getComponentByteSize(accessor.componentType) * getNumComponents(accessor.type) > bufferView.byteLength)
+				return Error::InvalidGltf;
+		}
...
@@ -1072,6 +1080,10 @@ fg::Error fg::validate(const Asset& asset) {
 		if (bufferView.bufferIndex >= asset.buffers.size())
 			return Error::InvalidGltf;
 
+		if (const auto& buffer = asset.buffers[bufferView.bufferIndex];
+			bufferView.byteOffset + bufferView.byteLength > buffer.byteLength)
+			return Error::InvalidGltf;
```

---

### 3. Verification in v0.9.1 (Commit `705564d`)

1. **Where the check is applied**:
   Notice that the commit placed the bounds check **strictly inside `fastgltf::validate()`**.
2. **What `Parser::loadGltf()` does**:
   `Parser::loadGltf()` parses the JSON / GLB and returns `fastgltf::Expected<fastgltf::Asset>`. It **does not invoke `fastgltf::validate()`** automatically.
3. **Implication**:
   If an application calls `parser.loadGltf()` and immediately consumes accessors via `getAccessorElement`, `iterateAccessor`, or `copyFromAccessor` without manually running `fastgltf::validate()`, the out-of-bounds read in `deserializeComponent` **is still fully triggerable in v0.9.1**.
4. **Sparse Accessors Gaps**:
   Even if `fastgltf::validate()` is invoked, commit `ffebaa7` did not add extent checks for sparse index and value bufferViews (`indicesByteOffset`, `valuesByteOffset`).

---

### 4. Classification & Accounting Rules

- **Status in Pinned v0.9.1**: Still present when `Parser::loadGltf` is called without explicit `validate()`.
- **Reproducer Artifact**: Preserved in `findings/known/issue_144_reproducer.gltf`.
- **Rule for Experiment**: Any crash exhibiting signature `*@*deserializeComponent*` or matching Issue #144 is classified as:
  ```text
  KNOWN_FINDING
  ```
  It is **strictly excluded** from the new vulnerability findings count for the project.
