# Issue 02: glTF Accessor & Buffer View Out-of-Bounds Memory Read

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
