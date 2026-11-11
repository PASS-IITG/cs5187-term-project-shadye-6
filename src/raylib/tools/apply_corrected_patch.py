#!/usr/bin/env python3
import sys, subprocess

path = "/mnt/c/Users/dxksh/Desktop/swa/raylib-src/src/rmodels.c"

# Restore pristine rmodels.c from git
subprocess.run(["git", "checkout", "src/rmodels.c"], cwd="/mnt/c/Users/dxksh/Desktop/swa/raylib-src", check=True)

with open(path, "rb") as f:
    raw = f.read()
crlf = b"\r\n" in raw
text = raw.decode("utf-8")

# 1. Callback size validation
old_cb = """static cgltf_result LoadFileGLTFCallback(const struct cgltf_memory_options *memoryOptions, const struct cgltf_file_options *fileOptions, const char *path, cgltf_size *size, void **data)
{
    int filesize;
    unsigned char *filedata = LoadFileData(path, &filesize);

    if (filedata == NULL) return cgltf_result_io_error;

    *size = filesize;
    *data = filedata;

    return cgltf_result_success;
}"""

new_cb = """static cgltf_result LoadFileGLTFCallback(const struct cgltf_memory_options *memoryOptions, const struct cgltf_file_options *fileOptions, const char *path, cgltf_size *size, void **data)
{
    int filesize;
    unsigned char *filedata = LoadFileData(path, &filesize);

    if (filedata == NULL) return cgltf_result_io_error;

    if ((size != NULL) && (*size > 0) && ((cgltf_size)filesize < *size))
    {
        TRACELOG(LOG_WARNING, "MODEL: [%s] File size smaller than expected buffer size", path);
        UnloadFileData(filedata);
        return cgltf_result_data_too_short;
    }

    if (size != NULL) *size = filesize;
    *data = filedata;

    return cgltf_result_success;
}"""

# 2. Replace LOAD_ATTRIBUTE and LOAD_ATTRIBUTE_CAST
old_macro = """    // Macro to simplify attributes loading code
    #define LOAD_ATTRIBUTE(accesor, numComp, srcType, dstPtr) LOAD_ATTRIBUTE_CAST(accesor, numComp, srcType, dstPtr, srcType)

    #define LOAD_ATTRIBUTE_CAST(accesor, numComp, srcType, dstPtr, dstType) \\
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

new_macro = """    // Macro to simplify attributes loading code
    #define LOAD_ATTRIBUTE(accesor, numComp, srcType, dstPtr) LOAD_ATTRIBUTE_CAST(accesor, numComp, srcType, dstPtr, srcType)

    #define LOAD_ATTRIBUTE_CAST(accesor, numComp, srcType, dstPtr, dstType) \\
    { \\
        if (((accesor) != NULL) && ((dstPtr) != NULL) && ((accesor)->count > 0)) \\
        { \\
            cgltf_size _elemSize = (cgltf_size)(numComp)*sizeof(srcType); \\
            cgltf_size _stride = (accesor)->stride ? (accesor)->stride : _elemSize; \\
            if ((accesor)->buffer_view != NULL) \\
            { \\
                if (((accesor)->buffer_view->buffer == NULL) || ((accesor)->buffer_view->buffer->data == NULL)) \\
                { \\
                    memset((dstPtr), 0, (size_t)(accesor)->count*(size_t)(numComp)*sizeof(dstType)); \\
                } \\
                else \\
                { \\
                    cgltf_size _bv_off = (accesor)->buffer_view->offset; \\
                    cgltf_size _bv_sz = (accesor)->buffer_view->size; \\
                    cgltf_size _b_sz = (accesor)->buffer_view->buffer->size; \\
                    bool _bv_valid = (_bv_off <= _b_sz) && (_bv_sz <= _b_sz - _bv_off); \\
                    bool _acc_valid = false; \\
                    if (_bv_valid && ((accesor)->offset <= _bv_sz)) \\
                    { \\
                        cgltf_size _rem = _bv_sz - (accesor)->offset; \\
                        if ((accesor)->count == 1) _acc_valid = (_elemSize <= _rem); \\
                        else \\
                        { \\
                            cgltf_size _span = (accesor)->count - 1; \\
                            if (_elemSize <= _rem) \\
                            { \\
                                cgltf_size _space_for_stride = _rem - _elemSize; \\
                                _acc_valid = (_stride == 0) || (_span <= _space_for_stride/_stride); \\
                            } \\
                        } \\
                    } \\
                    if (_acc_valid) \\
                    { \\
                        const unsigned char *_base = (const unsigned char *)(accesor)->buffer_view->buffer->data + (accesor)->buffer_view->offset + (accesor)->offset; \\
                        for (cgltf_size _k = 0; _k < (accesor)->count; _k++) \\
                        { \\
                            const srcType *_src = (const srcType *)(_base + _k*_stride); \\
                            for (int _l = 0; _l < (numComp); _l++) \\
                            { \\
                                (dstPtr)[(cgltf_size)(numComp)*_k + _l] = (dstType)_src[_l]; \\
                            } \\
                        } \\
                    } \\
                    else \\
                    { \\
                        TRACELOG(LOG_WARNING, "MODEL: [%s] glTF accessor buffer range exceeds bufferView size", fileName); \\
                        memset((dstPtr), 0, (size_t)(accesor)->count*(size_t)(numComp)*sizeof(dstType)); \\
                    } \\
                } \\
            } \\
            else \\
            { \\
                memset((dstPtr), 0, (size_t)(accesor)->count*(size_t)(numComp)*sizeof(dstType)); \\
            } \\
            if ((accesor)->is_sparse) \\
            { \\
                cgltf_accessor_sparse *_sp = &(accesor)->sparse; \\
                if ((_sp->indices_buffer_view != NULL) && (_sp->indices_buffer_view->buffer != NULL) && \\
                    (_sp->indices_buffer_view->buffer->data != NULL) && (_sp->values_buffer_view != NULL) && \\
                    (_sp->values_buffer_view->buffer != NULL) && (_sp->values_buffer_view->buffer->data != NULL)) \\
                { \\
                    cgltf_size _idx_sz = cgltf_component_size(_sp->indices_component_type); \\
                    cgltf_size _idx_b_sz = _sp->indices_buffer_view->buffer->size; \\
                    cgltf_size _val_b_sz = _sp->values_buffer_view->buffer->size; \\
                    cgltf_size _idx_bv_off = _sp->indices_buffer_view->offset; \\
                    cgltf_size _idx_bv_sz = _sp->indices_buffer_view->size; \\
                    cgltf_size _val_bv_off = _sp->values_buffer_view->offset; \\
                    cgltf_size _val_bv_sz = _sp->values_buffer_view->size; \\
                    bool _sp_bv_valid = (_idx_bv_off <= _idx_b_sz) && (_idx_bv_sz <= _idx_b_sz - _idx_bv_off) && \\
                                        (_val_bv_off <= _val_b_sz) && (_val_bv_sz <= _val_b_sz - _val_bv_off); \\
                    bool _idx_fit = _sp_bv_valid && (_idx_sz > 0) && \\
                                    (_sp->indices_byte_offset <= _idx_bv_sz) && \\
                                    (_sp->count <= (_idx_bv_sz - _sp->indices_byte_offset)/_idx_sz); \\
                    bool _val_fit = _sp_bv_valid && (_elemSize > 0) && \\
                                    (_sp->values_byte_offset <= _val_bv_sz) && \\
                                    (_sp->count <= (_val_bv_sz - _sp->values_byte_offset)/_elemSize); \\
                    if (_idx_fit && _val_fit) \\
                    { \\
                        const unsigned char *_idx_base = (const unsigned char *)_sp->indices_buffer_view->buffer->data + \\
                                                         _sp->indices_buffer_view->offset + _sp->indices_byte_offset; \\
                        const unsigned char *_val_base = (const unsigned char *)_sp->values_buffer_view->buffer->data + \\
                                                         _sp->values_buffer_view->offset + _sp->values_byte_offset; \\
                        for (cgltf_size _si = 0; _si < _sp->count; _si++) \\
                        { \\
                            cgltf_size _target_idx = 0; \\
                            if (_sp->indices_component_type == cgltf_component_type_r_8u) \\
                                _target_idx = ((const unsigned char *)_idx_base)[_si]; \\
                            else if (_sp->indices_component_type == cgltf_component_type_r_16u) \\
                                _target_idx = ((const unsigned short *)_idx_base)[_si]; \\
                            else if (_sp->indices_component_type == cgltf_component_type_r_32u) \\
                                _target_idx = ((const unsigned int *)_idx_base)[_si]; \\
                            if (_target_idx < (accesor)->count) \\
                            { \\
                                const srcType *_val_src = (const srcType *)(_val_base + _si*_elemSize); \\
                                for (int _l = 0; _l < (numComp); _l++) \\
                                { \\
                                    (dstPtr)[(cgltf_size)(numComp)*_target_idx + _l] = (dstType)_val_src[_l]; \\
                                } \\
                            } \\
                            else \\
                            { \\
                                TRACELOG(LOG_WARNING, "MODEL: [%s] glTF sparse index out of bounds", fileName); \\
                            } \\
                        } \\
                    } \\
                    else \\
                    { \\
                        TRACELOG(LOG_WARNING, "MODEL: [%s] glTF sparse accessor buffer range exceeds bufferView size", fileName); \\
                    } \\
                } \\
                else \\
                { \\
                    TRACELOG(LOG_WARNING, "MODEL: [%s] glTF sparse accessor missing buffer view data", fileName); \\
                } \\
            } \\
        } \\
    }"""

# 3. Buffer loading failure handling
old_load = """        // Force reading data buffers (fills buffer_view->buffer->data)
        // NOTE: If an uri is defined to base64 data or external path, it's automatically loaded
        result = cgltf_load_buffers(&options, data, fileName);
        if (result != cgltf_result_success) TRACELOG(LOG_INFO, "MODEL: [%s] Failed to load mesh/material buffers", fileName);"""

new_load = """        // Force reading data buffers (fills buffer_view->buffer->data)
        // NOTE: If an uri is defined to base64 data or external path, it's automatically loaded
        result = cgltf_load_buffers(&options, data, fileName);
        if (result != cgltf_result_success)
        {
            TRACELOG(LOG_WARNING, "MODEL: [%s] Failed to load glTF buffers", fileName);
            cgltf_free(data);
            UnloadFileData(fileData);
            return model;
        }"""

# 4. Indices loading path: support sparse indices without base buffer_view
old_indices = """                // Load primitive indices data (if provided)
                if ((mesh->primitives[p].indices != NULL) && (mesh->primitives[p].indices->buffer_view != NULL))"""

new_indices = """                // Load primitive indices data (if provided)
                if ((mesh->primitives[p].indices != NULL) && ((mesh->primitives[p].indices->buffer_view != NULL) || mesh->primitives[p].indices->is_sparse))"""

# Normalize line breaks for matching
text_norm = text.replace("\r\n", "\n")
old_cb_norm = old_cb.replace("\r\n", "\n")
old_macro_norm = old_macro.replace("\r\n", "\n")
old_load_norm = old_load.replace("\r\n", "\n")
old_indices_norm = old_indices.replace("\r\n", "\n")

assert old_cb_norm in text_norm, "old_cb not found!"
assert old_macro_norm in text_norm, "old_macro not found!"
assert old_load_norm in text_norm, "old_load not found!"
assert old_indices_norm in text_norm, "old_indices not found!"

text_norm = text_norm.replace(old_cb_norm, new_cb.replace("\r\n", "\n"))
text_norm = text_norm.replace(old_macro_norm, new_macro.replace("\r\n", "\n"))
text_norm = text_norm.replace(old_load_norm, new_load.replace("\r\n", "\n"))
text_norm = text_norm.replace(old_indices_norm, new_indices.replace("\r\n", "\n"))

final_bytes = text_norm.replace("\n", "\r\n").encode("utf-8") if crlf else text_norm.encode("utf-8")

with open(path, "wb") as f:
    f.write(final_bytes)

print("rmodels.c successfully patched with full safety checks!")
