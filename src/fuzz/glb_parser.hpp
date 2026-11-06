#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>
#include <string>

namespace fastgltf_fuzz {

constexpr uint32_t GLB_MAGIC_GLTF = 0x46546C67; // "glTF"
constexpr uint32_t GLB_CHUNK_JSON  = 0x4E4F534A; // "JSON"
constexpr uint32_t GLB_CHUNK_BIN   = 0x004E4942; // "BIN\0"

struct GlbChunk {
    uint32_t chunkLength = 0;
    uint32_t chunkType = 0;
    std::vector<uint8_t> data;
};

struct GlbContainer {
    uint32_t magic = GLB_MAGIC_GLTF;
    uint32_t version = 2;
    uint32_t declaredTotalLength = 0;
    std::vector<GlbChunk> chunks;
};

class GlbParser {
public:
    static bool parse(const uint8_t* data, size_t size, GlbContainer& out);
    static std::vector<uint8_t> serialize(const GlbContainer& container, bool repairLengths = true);
    static bool isGlb(const uint8_t* data, size_t size);
};

} // namespace fastgltf_fuzz
