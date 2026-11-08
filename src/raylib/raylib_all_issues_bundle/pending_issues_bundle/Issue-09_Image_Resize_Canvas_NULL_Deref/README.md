# Issue 09: ImageResizeCanvas() NULL Pointer Dereference on Allocation Failure

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
