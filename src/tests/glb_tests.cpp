#include "../fuzz/glb_parser.hpp"
#include <cassert>
#include <iostream>
#include <vector>
#include <cstring>

int main() {
    std::cout << "[Test] Running GLB parser unit tests..." << std::endl;

    // Build a minimal valid GLB
    fastgltf_fuzz::GlbContainer container;
    container.magic = fastgltf_fuzz::GLB_MAGIC_GLTF;
    container.version = 2;

    std::string jsonPayload = "{\"asset\":{\"version\":\"2.0\"}}";
    fastgltf_fuzz::GlbChunk jsonChunk;
    jsonChunk.chunkType = fastgltf_fuzz::GLB_CHUNK_JSON;
    jsonChunk.data.assign(jsonPayload.begin(), jsonPayload.end());
    jsonChunk.chunkLength = static_cast<uint32_t>(jsonChunk.data.size());

    fastgltf_fuzz::GlbChunk binChunk;
    binChunk.chunkType = fastgltf_fuzz::GLB_CHUNK_BIN;
    binChunk.data = { 0x01, 0x02, 0x03, 0x04 };
    binChunk.chunkLength = 4;

    container.chunks.push_back(jsonChunk);
    container.chunks.push_back(binChunk);

    // Test 1: Serialization with length repair
    auto serialized = fastgltf_fuzz::GlbParser::serialize(container, true);
    assert(serialized.size() >= 12);
    assert(fastgltf_fuzz::GlbParser::isGlb(serialized.data(), serialized.size()));
    std::cout << "  Passed: GLB serialization with repair" << std::endl;

    // Test 2: Parsing back
    fastgltf_fuzz::GlbContainer parsed;
    bool ok = fastgltf_fuzz::GlbParser::parse(serialized.data(), serialized.size(), parsed);
    assert(ok);
    assert(parsed.magic == fastgltf_fuzz::GLB_MAGIC_GLTF);
    assert(parsed.version == 2);
    assert(parsed.chunks.size() == 2);
    assert(parsed.chunks[0].chunkType == fastgltf_fuzz::GLB_CHUNK_JSON);
    assert(parsed.chunks[1].chunkType == fastgltf_fuzz::GLB_CHUNK_BIN);
    std::cout << "  Passed: GLB roundtrip parsing" << std::endl;

    // Test 3: Truncated input safety
    fastgltf_fuzz::GlbContainer truncated;
    bool truncOk = fastgltf_fuzz::GlbParser::parse(serialized.data(), 10, truncated);
    assert(!truncOk); // Size < 12 must fail gracefully
    std::cout << "  Passed: Truncated input bounds safety" << std::endl;

    std::cout << "[Test] All GLB parser tests passed!" << std::endl;
    return 0;
}
