#include "raylib.h"
#include <stdio.h>

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <gltf_file>\n", argv[0]);
        return 1;
    }

    const char *path = argv[1];
    printf("=== Testing raylib LoadModel: %s ===\n", path);

    // Initialize headless window using memory platform / hidden window
    SetTraceLogLevel(LOG_WARNING);
    InitWindow(64, 64, "glTF test");

    Model model = LoadModel(path);
    if (IsModelValid(model)) {
        printf("LoadModel SUCCESS: meshCount=%d, materialCount=%d\n", 
               model.meshCount, model.materialCount);
        UnloadModel(model);
    } else {
        printf("LoadModel RETURNED INVALID MODEL\n");
    }

    CloseWindow();
    printf("Finished cleanly without crash\n");
    return 0;
}

