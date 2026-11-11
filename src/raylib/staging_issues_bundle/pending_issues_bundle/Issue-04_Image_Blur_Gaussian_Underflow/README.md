# Issue 04: Heap Buffer Underflow in ImageBlurGaussian()

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
