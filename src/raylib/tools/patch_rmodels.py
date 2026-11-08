path = '/mnt/c/Users/dxksh/Desktop/swa/raylib-src/src/rmodels.c'
content = open(path, 'r').read()

old_macro = """    #define LOAD_ATTRIBUTE_CAST(accesor, numComp, srcType, dstPtr, dstType) \\
    { \\
        int n = 0; \\
        srcType *buffer = (srcType *)accesor->buffer_view->buffer->data + accesor->buffer_view->offset/sizeof(srcType) + accesor->offset/sizeof(srcType); \\
        for (unsigned int k = 0; k < accesor->count; k++) \\
        {\\
            for (int l = 0; l < numComp; l++) \\
            {\\
                dstPtr[numComp*k + l] = (dstType)buffer[n + l];\\
            }\\
            n += (int)(accesor->stride/sizeof(srcType));\\
        }\\
    }"""

new_macro = """    #define LOAD_ATTRIBUTE_CAST(accesor, numComp, srcType, dstPtr, dstType) \\
    { \\
        if ((accesor->buffer_view == NULL) || (accesor->buffer_view->buffer == NULL) || (accesor->buffer_view->buffer->data == NULL)) \\
        { \\
            memset(dstPtr, 0, (accesor->count)*(numComp)*sizeof(dstType)); \\
        } \\
        else \\
        { \\
            int n = 0; \\
            srcType *buffer = (srcType *)accesor->buffer_view->buffer->data + accesor->buffer_view->offset/sizeof(srcType) + accesor->offset/sizeof(srcType); \\
            for (unsigned int k = 0; k < accesor->count; k++) \\
            {\\
                for (int l = 0; l < numComp; l++) \\
                {\\
                    dstPtr[numComp*k + l] = (dstType)buffer[n + l];\\
                }\\
                n += (int)(accesor->stride/sizeof(srcType));\\
            }\\
        } \\
    }"""

old_load = """        result = cgltf_load_buffers(&options, data, fileName);
        if (result != cgltf_result_success) TRACELOG(LOG_INFO, "MODEL: [%s] Failed to load mesh/material buffers", fileName);"""

new_load = """        result = cgltf_load_buffers(&options, data, fileName);
        if (result != cgltf_result_success)
        {
            TRACELOG(LOG_WARNING, "MODEL: [%s] Failed to load glTF buffers", fileName);
            cgltf_free(data);
            return model;
        }

        result = cgltf_validate(data);
        if (result != cgltf_result_success)
        {
            TRACELOG(LOG_WARNING, "MODEL: [%s] glTF validation failed", fileName);
            cgltf_free(data);
            return model;
        }"""

assert old_macro in content, "old_macro not found"
assert old_load in content, "old_load not found"

content = content.replace(old_macro, new_macro)
content = content.replace(old_load, new_load)

open(path, 'w').write(content)
print("Successfully patched rmodels.c with defensive checks!")

