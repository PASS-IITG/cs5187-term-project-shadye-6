#define CGLTF_IMPLEMENTATION
#include "src/external/cgltf.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <gltf_file>\n", argv[0]);
        return 1;
    }

    const char *path = argv[1];
    printf("=== Analyzing glTF: %s ===\n", path);

    cgltf_options options;
    memset(&options, 0, sizeof(options));

    cgltf_data *data = NULL;
    cgltf_result parse_res = cgltf_parse_file(&options, path, &data);
    printf("cgltf_parse_file: %s (%d)\n", 
           parse_res == cgltf_result_success ? "SUCCESS" : "FAILED", parse_res);

    if (parse_res != cgltf_result_success) {
        return 1;
    }

    cgltf_result load_res = cgltf_load_buffers(&options, data, path);
    printf("cgltf_load_buffers: %s (%d)\n", 
           load_res == cgltf_result_success ? "SUCCESS" : "FAILED", load_res);

    cgltf_result val_res = cgltf_validate(data);
    printf("cgltf_validate: %s (%d)\n", 
           val_res == cgltf_result_success ? "SUCCESS" : "FAILED", val_res);

    printf("Meshes: %zu, Accessors: %zu, BufferViews: %zu, Buffers: %zu\n",
           data->meshes_count, data->accessors_count, data->buffer_views_count, data->buffers_count);

    for (size_t i = 0; i < data->accessors_count; i++) {
        cgltf_accessor *acc = &data->accessors[i];
        printf("Accessor #%zu:\n", i);
        printf("  count: %zu, type: %d, component_type: %d\n", acc->count, acc->type, acc->component_type);
        printf("  buffer_view: %p\n", (void*)acc->buffer_view);
        if (acc->buffer_view) {
            printf("  buffer_view->offset: %zu, size: %zu, stride: %zu\n",
                   acc->buffer_view->offset, acc->buffer_view->size, acc->buffer_view->stride);
            printf("  buffer_view->buffer: %p\n", (void*)acc->buffer_view->buffer);
            if (acc->buffer_view->buffer) {
                printf("  buffer->size: %zu, data: %p, uri: %s\n",
                       acc->buffer_view->buffer->size, acc->buffer_view->buffer->data,
                       acc->buffer_view->buffer->uri ? acc->buffer_view->buffer->uri : "(null)");
            }
        }
        printf("  is_sparse: %d\n", acc->is_sparse);
    }

    for (size_t m = 0; m < data->meshes_count; m++) {
        cgltf_mesh *mesh = &data->meshes[m];
        printf("Mesh #%zu: primitives_count=%zu\n", m, mesh->primitives_count);
        for (size_t p = 0; p < mesh->primitives_count; p++) {
            cgltf_primitive *prim = &mesh->primitives[p];
            printf("  Primitive #%zu: attributes_count=%zu\n", p, prim->attributes_count);
            for (size_t a = 0; a < prim->attributes_count; a++) {
                cgltf_attribute *attr = &prim->attributes[a];
                printf("    Attr #%zu: name=%s, type=%d, index=%d, data_ptr=%p\n",
                       a, attr->name ? attr->name : "(null)", attr->type, attr->index, (void*)attr->data);
                if (attr->data) {
                    printf("      accessor buffer_view=%p, is_sparse=%d\n",
                           (void*)attr->data->buffer_view, attr->data->is_sparse);
                }
            }
        }
    }

    cgltf_free(data);
    return 0;
}

