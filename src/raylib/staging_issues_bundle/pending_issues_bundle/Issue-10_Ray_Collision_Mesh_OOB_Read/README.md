# Issue 10: Out-of-Bounds Mesh Index Array Read in GetRayCollisionMesh()

- **Vulnerable File:** `src/rmodels.c:4350-4354`
- **Component:** Models / Ray-Mesh Collision Detection
- **Status:** Pending
- **Vulnerability Type:** Out-of-Bounds Read (CWE-125)

## Description
In `GetRayCollisionMesh()`, triangle collision test loops over all index triplets:
```c
if (mesh.indices)
{
    a = vertdata[mesh.indices[i*3 + 0]];
    b = vertdata[mesh.indices[i*3 + 1]];
    c = vertdata[mesh.indices[i*3 + 2]];
}
```
Indices in `mesh.indices` are 16-bit integers (`unsigned short`). If the mesh has fewer vertices than an index reference (`mesh.indices[i*3 + k] >= mesh.vertexCount`), reading `vertdata[...]` accesses out-of-bounds heap memory past the `mesh.vertices` allocation, causing an illegal read / segmentation fault.

## Remediation
Validate that each index in the triplet is strictly less than `mesh.vertexCount` before accessing `vertdata`.
