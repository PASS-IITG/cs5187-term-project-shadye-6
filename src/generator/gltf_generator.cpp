#include "gltf_generator.hpp"
#include "../fuzz/glb_parser.hpp"
#include <fastgltf/base64.hpp>
#include <sstream>
#include <array>
#include <cstring>

namespace fastgltf_fuzz {

namespace {

std::string encodeBase64(const uint8_t* data, size_t size) {
    if (size == 0) return "";
    size_t encodedSize = fastgltf::base64::getEncodedSize(size);
    std::string result;
    result.resize(encodedSize);
    fastgltf::base64::encode_into(data, size, result.data());
    return result;
}

} // namespace

std::string GltfGenerator::generateJsonGltf(uint32_t seed) {
    // Generate a minimal valid triangle mesh
    // Buffer contains: 3 vertex positions (3 * 3 * 4 = 36 bytes) + 3 uint16 indices (6 bytes)
    float xOffset = static_cast<float>(seed % 10) * 0.1f;
    std::array<float, 9> positions = {
        0.0f + xOffset, 0.0f, 0.0f,
        1.0f + xOffset, 0.0f, 0.0f,
        0.5f + xOffset, 1.0f, 0.0f
    };
    std::array<uint16_t, 4> indices = { 0, 1, 2, 0 }; // 4 uint16 for 4-byte alignment

    std::vector<uint8_t> bufferData;
    bufferData.resize(sizeof(positions) + sizeof(indices));
    std::memcpy(bufferData.data(), positions.data(), sizeof(positions));
    std::memcpy(bufferData.data() + sizeof(positions), indices.data(), sizeof(indices));

    std::string b64 = encodeBase64(bufferData.data(), bufferData.size());

    std::ostringstream ss;
    ss << "{\n"
       << "  \"asset\": {\"version\": \"2.0\", \"generator\": \"fastgltf_fuzz\"},\n"
       << "  \"buffers\": [{\"byteLength\": " << bufferData.size() << ", \"uri\": \"data:application/octet-stream;base64," << b64 << "\"}],\n"
       << "  \"bufferViews\": [\n"
       << "    {\"buffer\": 0, \"byteOffset\": 0, \"byteLength\": 36, \"target\": 34962},\n"
       << "    {\"buffer\": 0, \"byteOffset\": 36, \"byteLength\": 6, \"target\": 34963}\n"
       << "  ],\n"
       << "  \"accessors\": [\n"
       << "    {\"bufferView\": 0, \"byteOffset\": 0, \"componentType\": 5126, \"count\": 3, \"type\": \"VEC3\", \"max\": [1.0, 1.0, 0.0], \"min\": [0.0, 0.0, 0.0]},\n"
       << "    {\"bufferView\": 1, \"byteOffset\": 0, \"componentType\": 5123, \"count\": 3, \"type\": \"SCALAR\", \"max\": [2], \"min\": [0]}\n"
       << "  ],\n"
       << "  \"meshes\": [{\"primitives\": [{\"attributes\": {\"POSITION\": 0}, \"indices\": 1}]}],\n"
       << "  \"nodes\": [{\"mesh\": 0}],\n"
       << "  \"scenes\": [{\"nodes\": [0]}],\n"
       << "  \"scene\": 0\n"
       << "}\n";
    return ss.str();
}

std::vector<uint8_t> GltfGenerator::generateGlb(uint32_t seed) {
    float xOffset = static_cast<float>(seed % 10) * 0.1f;
    std::array<float, 9> positions = {
        0.0f + xOffset, 0.0f, 0.0f,
        1.0f + xOffset, 0.0f, 0.0f,
        0.5f + xOffset, 1.0f, 0.0f
    };
    std::array<uint16_t, 4> indices = { 0, 1, 2, 0 };

    std::vector<uint8_t> binData;
    binData.resize(sizeof(positions) + sizeof(indices));
    std::memcpy(binData.data(), positions.data(), sizeof(positions));
    std::memcpy(binData.data() + sizeof(positions), indices.data(), sizeof(indices));

    std::ostringstream ss;
    ss << "{\"asset\":{\"version\":\"2.0\"},"
       << "\"buffers\":[{\"byteLength\":" << binData.size() << "}],"
       << "\"bufferViews\":["
       << "{\"buffer\":0,\"byteOffset\":0,\"byteLength\":36,\"target\":34962},"
       << "{\"buffer\":0,\"byteOffset\":36,\"byteLength\":6,\"target\":34963}],"
       << "\"accessors\":["
       << "{\"bufferView\":0,\"byteOffset\":0,\"componentType\":5126,\"count\":3,\"type\":\"VEC3\"},"
       << "{\"bufferView\":1,\"byteOffset\":0,\"componentType\":5123,\"count\":3,\"type\":\"SCALAR\"}],"
       << "\"meshes\":[{\"primitives\":[{\"attributes\":{\"POSITION\":0},\"indices\":1}]}],"
       << "\"nodes\":[{\"mesh\":0}],\"scenes\":[{\"nodes\":[0]}],\"scene\":0}";

    std::string jsonStr = ss.str();

    GlbContainer container;
    container.magic = GLB_MAGIC_GLTF;
    container.version = 2;

    GlbChunk jsonChunk;
    jsonChunk.chunkType = GLB_CHUNK_JSON;
    jsonChunk.data.assign(reinterpret_cast<const uint8_t*>(jsonStr.data()),
                          reinterpret_cast<const uint8_t*>(jsonStr.data() + jsonStr.size()));
    jsonChunk.chunkLength = static_cast<uint32_t>(jsonChunk.data.size());

    GlbChunk binChunk;
    binChunk.chunkType = GLB_CHUNK_BIN;
    binChunk.data = std::move(binData);
    binChunk.chunkLength = static_cast<uint32_t>(binChunk.data.size());

    container.chunks.push_back(std::move(jsonChunk));
    container.chunks.push_back(std::move(binChunk));

    return GlbParser::serialize(container, true);
}

std::string GltfGenerator::generateSparseJsonGltf(uint32_t seed) {
    // 3 base positions + 1 sparse override
    std::array<float, 9> basePositions = {
        0.0f, 0.0f, 0.0f,
        1.0f, 0.0f, 0.0f,
        0.5f, 1.0f, 0.0f
    };
    std::array<uint16_t, 2> sparseIndex = { 1, 0 }; // override vertex 1
    std::array<float, 3> sparseValue = { 2.0f, 2.0f, 0.0f };

    std::vector<uint8_t> bufferData;
    bufferData.resize(sizeof(basePositions) + sizeof(sparseIndex) + sizeof(sparseValue));
    size_t off = 0;
    std::memcpy(bufferData.data() + off, basePositions.data(), sizeof(basePositions));
    off += sizeof(basePositions);
    std::memcpy(bufferData.data() + off, sparseIndex.data(), sizeof(sparseIndex));
    off += sizeof(sparseIndex);
    std::memcpy(bufferData.data() + off, sparseValue.data(), sizeof(sparseValue));

    std::string b64 = encodeBase64(bufferData.data(), bufferData.size());

    std::ostringstream ss;
    ss << "{\n"
       << "  \"asset\": {\"version\": \"2.0\"},\n"
       << "  \"buffers\": [{\"byteLength\": " << bufferData.size() << ", \"uri\": \"data:application/octet-stream;base64," << b64 << "\"}],\n"
       << "  \"bufferViews\": [\n"
       << "    {\"buffer\": 0, \"byteOffset\": 0, \"byteLength\": 36},\n"
       << "    {\"buffer\": 0, \"byteOffset\": 36, \"byteLength\": 4},\n"
       << "    {\"buffer\": 0, \"byteOffset\": 40, \"byteLength\": 12}\n"
       << "  ],\n"
       << "  \"accessors\": [\n"
       << "    {\n"
       << "      \"bufferView\": 0, \"byteOffset\": 0, \"componentType\": 5126, \"count\": 3, \"type\": \"VEC3\",\n"
       << "      \"sparse\": {\n"
       << "        \"count\": 1,\n"
       << "        \"indices\": {\"bufferView\": 1, \"byteOffset\": 0, \"componentType\": 5123},\n"
       << "        \"values\": {\"bufferView\": 2, \"byteOffset\": 0}\n"
       << "      }\n"
       << "    }\n"
       << "  ],\n"
       << "  \"meshes\": [{\"primitives\": [{\"attributes\": {\"POSITION\": 0}}]}],\n"
       << "  \"nodes\": [{\"mesh\": 0}], \"scenes\": [{\"nodes\": [0]}], \"scene\": 0\n"
       << "}\n";
    return ss.str();
}

} // namespace fastgltf_fuzz
