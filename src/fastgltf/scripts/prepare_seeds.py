#!/usr/bin/env python3
"""
Seed Corpus Preparation Script for fastgltf Fuzzing
Generates small valid glTF JSON, GLB, and copies test resources,
wrapping each file with the fuzzer envelope [profile_byte][payload...].
"""

import os
import shutil
import subprocess

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.dirname(SCRIPT_DIR)
SEED_DIR = os.path.join(ROOT_DIR, "corpus", "seed")
TEST_GLTF_DIR = os.path.join(ROOT_DIR, "external", "fastgltf", "tests", "gltf")

os.makedirs(SEED_DIR, exist_ok=True)

# Helper to write enveloped file
def write_seed(filename, profile_byte, payload_bytes):
    out_path = os.path.join(SEED_DIR, filename)
    with open(out_path, "wb") as f:
        f.write(bytes([profile_byte]) + payload_bytes)
    print(f"Created seed: {filename} ({len(payload_bytes) + 1} bytes, profile {profile_byte})")

# 1. Minimal glTF JSON
minimal_json = b'{"asset":{"version":"2.0"}}'
write_seed("seed_minimal.gltf", 0, minimal_json)
write_seed("seed_minimal_p1.gltf", 1, minimal_json)

# 2. Triangle mesh with POSITION and indices (36 bytes pos + 6 bytes indices + 2 pad = 44 bytes)
# 9 floats (36 bytes) + 4 uint16 (8 bytes: 0, 1, 2, 0) = 44 bytes
triangle_payload = b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
                   b"\x00\x00\x80\x3f\x00\x00\x00\x00\x00\x00\x00\x00" \
                   b"\x00\x00\x00\x3f\x00\x00\x80\x3f\x00\x00\x00\x00" \
                   b"\x00\x00\x01\x00\x02\x00\x00\x00"
import base64
triangle_b64 = base64.b64encode(triangle_payload).decode("ascii")

triangle_json = f'''{{
  "asset": {{"version": "2.0"}},
  "buffers": [{{"byteLength": 44, "uri": "data:application/octet-stream;base64,{triangle_b64}"}}],
  "bufferViews": [
    {{"buffer": 0, "byteOffset": 0, "byteLength": 36, "target": 34962}},
    {{"buffer": 0, "byteOffset": 36, "byteLength": 8, "target": 34963}}
  ],
  "accessors": [
    {{"bufferView": 0, "byteOffset": 0, "componentType": 5126, "count": 3, "type": "VEC3", "max": [1.0, 1.0, 0.0], "min": [0.0, 0.0, 0.0]}},
    {{"bufferView": 1, "byteOffset": 0, "componentType": 5123, "count": 3, "type": "SCALAR", "max": [2], "min": [0]}}
  ],
  "meshes": [{{"primitives": [{{"attributes": {{"POSITION": 0}}, "indices": 1}}]}}],
  "nodes": [{{"mesh": 0}}],
  "scenes": [{{"nodes": [0]}}],
  "scene": 0
}}'''.encode("utf-8")
write_seed("seed_triangle.gltf", 0, triangle_json)
write_seed("seed_triangle_indices.gltf", 3, triangle_json)

# 3. Sparse accessor asset
# 3 base positions (36b) + 1 sparse index uint16 (4b padded) + 1 sparse value vec3 (12b) = 52 bytes
sparse_payload = (b"\x00" * 36) + (b"\x01\x00\x00\x00") + (b"\x00\x00\x00\x40\x00\x00\x00\x40\x00\x00\x00\x00")
sparse_b64 = base64.b64encode(sparse_payload).decode("ascii")

sparse_json = f'''{{
  "asset": {{"version": "2.0"}},
  "buffers": [{{"byteLength": 52, "uri": "data:application/octet-stream;base64,{sparse_b64}"}}],
  "bufferViews": [
    {{"buffer": 0, "byteOffset": 0, "byteLength": 36}},
    {{"buffer": 0, "byteOffset": 36, "byteLength": 4}},
    {{"buffer": 0, "byteOffset": 40, "byteLength": 12}}
  ],
  "accessors": [
    {{
      "bufferView": 0, "byteOffset": 0, "componentType": 5126, "count": 3, "type": "VEC3",
      "sparse": {{
        "count": 1,
        "indices": {{"bufferView": 1, "byteOffset": 0, "componentType": 5123}},
        "values": {{"bufferView": 2, "byteOffset": 0}}
      }}
    }}
  ],
  "meshes": [{{"primitives": [{{"attributes": {{"POSITION": 0}}}}]}}],
  "nodes": [{{"mesh": 0}}],
  "scenes": [{{"nodes": [0]}}],
  "scene": 0
}}'''.encode("utf-8")
write_seed("seed_sparse.gltf", 0, sparse_json)

# 4. Multi-node transforms
nodes_json = b'''{
  "asset": {"version": "2.0"},
  "nodes": [
    {"children": [1], "translation": [1.0, 2.0, 3.0]},
    {"matrix": [1,0,0,0, 0,1,0,0, 0,0,1,0, 0,0,0,1]}
  ],
  "scenes": [{"nodes": [0]}],
  "scene": 0
}'''
write_seed("seed_nodes.gltf", 2, nodes_json)

# 5. Extension tests from fastgltf repository
if os.path.exists(TEST_GLTF_DIR):
    for f in os.listdir(TEST_GLTF_DIR):
        if f.endswith(".gltf"):
            src_path = os.path.join(TEST_GLTF_DIR, f)
            with open(src_path, "rb") as rf:
                content = rf.read()
            write_seed(f"seed_{f}", 0, content)

# 6. Generate GLB seeds using procedural generator test binary if built
glb_generator_bin = os.path.join(ROOT_DIR, "build-asan", "generator_tests")
if os.path.exists(glb_generator_bin):
    # Run a small python snippet to construct minimal GLB bytes
    # GLB header: magic(glTF), version(2), length, JSON chunk
    json_chunk_data = b'{"asset":{"version":"2.0"},"buffers":[{"byteLength":4}],"bufferViews":[{"buffer":0,"byteOffset":0,"byteLength":4}],"accessors":[{"bufferView":0,"byteOffset":0,"componentType":5126,"count":1,"type":"SCALAR"}]}'
    # pad JSON chunk to multiple of 4 with space
    pad_len = (4 - (len(json_chunk_data) % 4)) % 4
    json_chunk_padded = json_chunk_data + (b' ' * pad_len)
    
    bin_chunk_data = b'\x00\x00\x80\x3f' # float 1.0
    
    total_len = 12 + (8 + len(json_chunk_padded)) + (8 + len(bin_chunk_data))
    
    import struct
    glb_header = struct.pack("<III", 0x46546C67, 2, total_len)
    json_header = struct.pack("<II", len(json_chunk_padded), 0x4E4F534A)
    bin_header = struct.pack("<II", len(bin_chunk_data), 0x004E4942)
    
    glb_bytes = glb_header + json_header + json_chunk_padded + bin_header + bin_chunk_data
    write_seed("seed_box.glb", 0, glb_bytes)
    write_seed("seed_box_p1.glb", 1, glb_bytes)

print(f"\nSuccessfully prepared seed corpus in {SEED_DIR}")
