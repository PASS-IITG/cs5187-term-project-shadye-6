#include "../fuzz/guarded_buffer_adapter.hpp"
#include <fastgltf/types.hpp>
#include <cassert>
#include <iostream>
#include <vector>

int main() {
    std::cout << "[Test] Running GuardedBufferDataAdapter tests..." << std::endl;

    fastgltf::Asset asset;

    // Buffer 0: 32 bytes
    fastgltf::Buffer buf;
    buf.byteLength = 32;
    std::vector<std::byte> rawBytes(32, std::byte{0xAB});
    fastgltf::StaticVector<std::byte> staticBytes(rawBytes.size());
    std::memcpy(staticBytes.data(), rawBytes.data(), rawBytes.size());
    buf.data = fastgltf::sources::Array{ std::move(staticBytes) };
    asset.buffers.push_back(std::move(buf));

    // BufferView 0: offset 0, length 16 (valid)
    fastgltf::BufferView bv0;
    bv0.bufferIndex = 0;
    bv0.byteOffset = 0;
    bv0.byteLength = 16;
    asset.bufferViews.push_back(std::move(bv0));

    // BufferView 1: offset 24, length 16 (overflows past 32 bytes: 24 + 16 = 40)
    fastgltf::BufferView bv1;
    bv1.bufferIndex = 0;
    bv1.byteOffset = 24;
    bv1.byteLength = 16;
    asset.bufferViews.push_back(std::move(bv1));

    fastgltf_fuzz::GuardedBufferDataAdapter adapter;

    // Test 1: Valid bufferView extraction
    auto span0 = adapter(asset, 0);
    assert(span0.size() == 16);
    assert(span0[0] == std::byte{0xAB});
    std::cout << "  Passed: Valid bufferView isolation" << std::endl;

    // Test 2: Out of bounds detection
    auto span1 = adapter(asset, 1);
    assert(span1.size() == 16);
    assert(adapter.hadBoundsViolation());
    std::cout << "  Passed: Bounds violation detected safely without crashing" << std::endl;

    // Test 3: Invalid bufferView index
    auto spanInvalid = adapter(asset, 999);
    assert(spanInvalid.empty());
    std::cout << "  Passed: Invalid index handling" << std::endl;

    std::cout << "[Test] All adapter tests passed!" << std::endl;
    return 0;
}
