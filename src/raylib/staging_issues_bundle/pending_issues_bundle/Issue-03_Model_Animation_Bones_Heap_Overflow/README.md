# Issue 03: Heap Buffer Overflow in UpdateModelAnimationBones()

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
