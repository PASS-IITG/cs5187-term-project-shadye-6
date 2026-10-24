#include "../fuzz/custom_mutator.hpp"
#include <cassert>
#include <iostream>
#include <vector>
#include <cstring>

int main() {
    std::cout << "[Test] Running mutator unit tests..." << std::endl;

    // Test 1: MaxSize adherence
    std::string testJson = "{\"asset\":{\"version\":\"2.0\"},\"buffers\":[{\"byteLength\":10}]}";
    std::vector<uint8_t> buffer(200);
    buffer[0] = 0; // profile byte
    std::memcpy(buffer.data() + 1, testJson.data(), testJson.size());
    size_t inSize = 1 + testJson.size();
    size_t maxSize = 100;

    size_t outSize = fastgltf_fuzz::mutatePayload(buffer.data(), inSize, maxSize, 12345, fastgltf_fuzz::FuzzMode::Struct);
    assert(outSize <= maxSize);
    assert(outSize > 0);
    std::cout << "  Passed: MaxSize bound respected (" << outSize << " <= " << maxSize << ")" << std::endl;

    // Test 2: Determinism check (same seed gives same result)
    std::vector<uint8_t> b1 = buffer;
    std::vector<uint8_t> b2 = buffer;
    size_t s1 = fastgltf_fuzz::mutatePayload(b1.data(), inSize, maxSize, 42, fastgltf_fuzz::FuzzMode::Struct);
    size_t s2 = fastgltf_fuzz::mutatePayload(b2.data(), inSize, maxSize, 42, fastgltf_fuzz::FuzzMode::Struct);
    assert(s1 == s2);
    assert(std::memcmp(b1.data(), b2.data(), s1) == 0);
    std::cout << "  Passed: Mutator determinism for same seed" << std::endl;

    // Test 3: Byte mode vs Struct mode
    size_t sByte = fastgltf_fuzz::mutatePayload(b1.data(), inSize, maxSize, 99, fastgltf_fuzz::FuzzMode::Byte);
    assert(sByte <= maxSize);
    std::cout << "  Passed: Byte mode mutation" << std::endl;

    std::cout << "[Test] All mutator unit tests passed!" << std::endl;
    return 0;
}
