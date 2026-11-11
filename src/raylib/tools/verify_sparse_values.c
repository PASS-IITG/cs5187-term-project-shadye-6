#include "raylib.h"
#include <stdio.h>
#include <math.h>

int main(void) {
    SetTraceLogLevel(LOG_INFO);
    InitWindow(64, 64, "sparse test");

    Model model = LoadModel("/tmp/gltf_spec_tests/test_B_sparse_accessor.gltf");
    printf("DEBUG: model.meshCount = %d\n", model.meshCount);
    printf("DEBUG: model.materialCount = %d\n", model.materialCount);
    printf("DEBUG: model.meshes = %p\n", (void*)model.meshes);
    printf("DEBUG: model.materials = %p\n", (void*)model.materials);
    printf("DEBUG: model.meshMaterial = %p\n", (void*)model.meshMaterial);
    printf("DEBUG: IsModelValid = %d\n", IsModelValid(model));

    if (model.meshCount > 0 && model.meshes != NULL) {
        Mesh m = model.meshes[0];
        printf("DEBUG: Mesh 0 vertexCount = %d, vertices = %p\n", m.vertexCount, (void*)m.vertices);
        if (m.vertices != NULL) {
            for (int i = 0; i < m.vertexCount; i++) {
                printf("  Vertex %d: (%.2f, %.2f, %.2f)\n", i, m.vertices[3*i], m.vertices[3*i+1], m.vertices[3*i+2]);
            }
        }
    }

    UnloadModel(model);
    CloseWindow();
    return 0;
}
