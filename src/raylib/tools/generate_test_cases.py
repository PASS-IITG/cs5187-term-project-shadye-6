#!/usr/bin/env python3
import os, json, base64, struct

TEST_DIR = "/tmp/gltf_spec_tests"
os.makedirs(TEST_DIR, exist_ok=True)

# 1 triangle: 3 vertices with XYZ floats (3 * 3 * 4 = 36 bytes)
positions = [
    0.0, 0.0, 0.0,
    1.0, 0.0, 0.0,
    0.0, 1.0, 0.0
]
pos_bytes = struct.pack("<9f", *positions)
pos_b64 = base64.b64encode(pos_bytes).decode("ascii")
pos_uri = f"data:application/octet-stream;base64,{pos_b64}"

def base_gltf(accessor, buffer_views=None, buffers=None):
    if buffer_views is None:
        buffer_views = [{
            "buffer": 0,
            "byteOffset": 0,
            "byteLength": len(pos_bytes)
        }]
    if buffers is None:
        buffers = [{
            "byteLength": len(pos_bytes),
            "uri": pos_uri
        }]
    return {
        "asset": {"version": "2.0"},
        "scenes": [{"nodes": [0]}],
        "nodes": [{"mesh": 0}],
        "meshes": [{
            "primitives": [{
                "attributes": {
                    "POSITION": 0
                }
            }]
        }],
        "accessors": [accessor],
        "bufferViews": buffer_views,
        "buffers": buffers
    }

# Test A: Valid bufferView (Ordinary accessor)
acc_A = {
    "bufferView": 0,
    "byteOffset": 0,
    "componentType": 5126, # FLOAT
    "count": 3,
    "type": "VEC3",
    "max": [1.0, 1.0, 0.0],
    "min": [0.0, 0.0, 0.0]
}
with open(f"{TEST_DIR}/test_A_valid_bufferview.gltf", "w") as f:
    json.dump(base_gltf(acc_A), f, indent=2)

# Test B: No bufferView, with sparse data (valid glTF 2.0 spec)
# 3 vertices, base is all zeros, sparse overrides vertex 1
sparse_indices = struct.pack("<1I", 1) # index 1
sparse_values = struct.pack("<3f", 1.0, 0.0, 0.0) # new position
sparse_bytes = sparse_indices + sparse_values
sparse_b64 = base64.b64encode(sparse_bytes).decode("ascii")

sparse_bv = [
    {"buffer": 0, "byteOffset": 0, "byteLength": len(sparse_indices)},
    {"buffer": 0, "byteOffset": len(sparse_indices), "byteLength": len(sparse_values)}
]
sparse_buf = [{"byteLength": len(sparse_bytes), "uri": f"data:application/octet-stream;base64,{sparse_b64}"}]

acc_B = {
    "componentType": 5126,
    "count": 3,
    "type": "VEC3",
    "max": [1.0, 0.0, 0.0],
    "min": [0.0, 0.0, 0.0],
    "sparse": {
        "count": 1,
        "indices": {
            "bufferView": 0,
            "byteOffset": 0,
            "componentType": 5125 # UNSIGNED_INT
        },
        "values": {
            "bufferView": 1,
            "byteOffset": 0
        }
    }
}
with open(f"{TEST_DIR}/test_B_sparse_accessor.gltf", "w") as f:
    json.dump(base_gltf(acc_B, sparse_bv, sparse_buf), f, indent=2)

# Test C: No bufferView, no sparse data (all-zero accessor)
acc_C = {
    "componentType": 5126,
    "count": 3,
    "type": "VEC3",
    "max": [0.0, 0.0, 0.0],
    "min": [0.0, 0.0, 0.0]
}
with open(f"{TEST_DIR}/test_C_no_bufferview_no_sparse.gltf", "w") as f:
    json.dump(base_gltf(acc_C, [], []), f, indent=2)

# Test D: Valid bufferView, invalid buffer offset (offset exceeds buffer)
acc_D = {
    "bufferView": 0,
    "byteOffset": 1000, # way out of bounds
    "componentType": 5126,
    "count": 3,
    "type": "VEC3",
    "max": [1.0, 1.0, 0.0],
    "min": [0.0, 0.0, 0.0]
}
with open(f"{TEST_DIR}/test_D_invalid_buffer_offset.gltf", "w") as f:
    json.dump(base_gltf(acc_D), f, indent=2)

# Test E: Sparse accessor with truncated sparse indices
acc_E = {
    "componentType": 5126,
    "count": 3,
    "type": "VEC3",
    "max": [1.0, 0.0, 0.0],
    "min": [0.0, 0.0, 0.0],
    "sparse": {
        "count": 100, # claims 100 indices, but bufferView only has 4 bytes
        "indices": {
            "bufferView": 0,
            "byteOffset": 0,
            "componentType": 5125
        },
        "values": {
            "bufferView": 1,
            "byteOffset": 0
        }
    }
}
with open(f"{TEST_DIR}/test_E_sparse_truncated_indices.gltf", "w") as f:
    json.dump(base_gltf(acc_E, sparse_bv, sparse_buf), f, indent=2)

# Test F: Sparse accessor with truncated sparse values
acc_F = {
    "componentType": 5126,
    "count": 3,
    "type": "VEC3",
    "max": [1.0, 0.0, 0.0],
    "min": [0.0, 0.0, 0.0],
    "sparse": {
        "count": 1,
        "indices": {
            "bufferView": 0,
            "byteOffset": 0,
            "componentType": 5125
        },
        "values": {
            "bufferView": 1,
            "byteOffset": 1000 # offset out of bounds
        }
    }
}
with open(f"{TEST_DIR}/test_F_sparse_truncated_values.gltf", "w") as f:
    json.dump(base_gltf(acc_F, sparse_bv, sparse_buf), f, indent=2)

# Test G: BufferView index out of range
acc_G = {
    "bufferView": 999, # non-existent bufferView
    "componentType": 5126,
    "count": 3,
    "type": "VEC3",
    "max": [1.0, 1.0, 0.0],
    "min": [0.0, 0.0, 0.0]
}
with open(f"{TEST_DIR}/test_G_bufferview_out_of_range.gltf", "w") as f:
    json.dump(base_gltf(acc_G), f, indent=2)

# Test H: Missing external buffer (uri = "missing.bin")
missing_buf = [{"byteLength": 100, "uri": "missing.bin"}]
missing_bv = [{"buffer": 0, "byteOffset": 0, "byteLength": 36}]
acc_H = {
    "bufferView": 0,
    "byteOffset": 0,
    "componentType": 5126,
    "count": 3,
    "type": "VEC3",
    "max": [1.0, 1.0, 0.0],
    "min": [0.0, 0.0, 0.0]
}
with open(f"{TEST_DIR}/test_H_missing_external_buffer.gltf", "w") as f:
    json.dump(base_gltf(acc_H, missing_bv, missing_buf), f, indent=2)

print("Generated all test files in", TEST_DIR)

