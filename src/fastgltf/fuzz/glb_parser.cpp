#include "glb_parser.hpp"
#include <cstring>
#include <algorithm>

namespace fastgltf_fuzz {

namespace {

inline uint32_t readU32LE(const uint8_t* p) {
    return static_cast<uint32_t>(p[0]) |
          (static_cast<uint32_t>(p[1]) << 8) |
          (static_cast<uint32_t>(p[2]) << 16) |
          (static_cast<uint32_t>(p[3]) << 24);
}

inline void writeU32LE(uint8_t* p, uint32_t val) {
    p[0] = static_cast<uint8_t>(val & 0xFF);
    p[1] = static_cast<uint8_t>((val >> 8) & 0xFF);
    p[2] = static_cast<uint8_t>((val >> 16) & 0xFF);
    p[3] = static_cast<uint8_t>((val >> 24) & 0xFF);
}

} // namespace

bool GlbParser::isGlb(const uint8_t* data, size_t size) {
    if (size < 4) return false;
    return readU32LE(data) == GLB_MAGIC_GLTF;
}

bool GlbParser::parse(const uint8_t* data, size_t size, GlbContainer& out) {
    if (size < 12) {
        return false;
    }

    out.magic = readU32LE(data);
    out.version = readU32LE(data + 4);
    out.declaredTotalLength = readU32LE(data + 8);
    out.chunks.clear();

    size_t offset = 12;
    while (offset + 8 <= size) {
        GlbChunk chunk;
        chunk.chunkLength = readU32LE(data + offset);
        chunk.chunkType = readU32LE(data + offset + 4);
        offset += 8;

        size_t available = (offset <= size) ? (size - offset) : 0;
        size_t toCopy = std::min(static_cast<size_t>(chunk.chunkLength), available);

        if (toCopy > 0) {
            chunk.data.assign(data + offset, data + offset + toCopy);
        }

        // Advance by chunk length padded to 4 bytes
        size_t padded = (chunk.chunkLength + 3) & ~size_t(3);
        if (padded > available) {
            offset = size; // Truncated chunk padding
        } else {
            offset += padded;
        }

        out.chunks.push_back(std::move(chunk));
    }

    return true;
}

std::vector<uint8_t> GlbParser::serialize(const GlbContainer& container, bool repairLengths) {
    std::vector<uint8_t> result;
    result.resize(12);

    writeU32LE(result.data(), container.magic);
    writeU32LE(result.data() + 4, container.version);

    for (const auto& chunk : container.chunks) {
        size_t chunkStart = result.size();
        result.resize(chunkStart + 8); // chunk header

        size_t padding = repairLengths ? ((4 - (chunk.data.size() % 4)) % 4) : 0;
        uint32_t len = repairLengths ? static_cast<uint32_t>(chunk.data.size() + padding) : chunk.chunkLength;
        writeU32LE(result.data() + chunkStart, len);
        writeU32LE(result.data() + chunkStart + 4, chunk.chunkType);

        result.insert(result.end(), chunk.data.begin(), chunk.data.end());

        if (repairLengths) {
            // glTF 2.0 spec: JSON padded with 0x20, BIN padded with 0x00
            uint8_t padByte = (chunk.chunkType == GLB_CHUNK_JSON) ? 0x20 : 0x00;
            for (size_t p = 0; p < padding; ++p) {
                result.push_back(padByte);
            }
        }
    }

    uint32_t totalLen = repairLengths ? static_cast<uint32_t>(result.size()) : container.declaredTotalLength;
    writeU32LE(result.data() + 8, totalLen);

    return result;
}

} // namespace fastgltf_fuzz
