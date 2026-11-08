#include <fastgltf/base64.hpp>
#include <cassert>
#include <iostream>
#include <string_view>
#include <cstring>

int main() {
    std::cout << "[Test] Running base64 tests..." << std::endl;

    // Test: Differential between SIMD and fallback on known string
    std::string_view testStr = "QUJDREVGR0hJSktMTU5PUA=="; // "ABCDEFGHIJKLMNOP"
    auto simd = fastgltf::base64::decode(testStr);
    auto fallback = fastgltf::base64::fallback_decode(testStr);

    assert(simd.size() == fallback.size());
    assert(std::memcmp(simd.data(), fallback.data(), simd.size()) == 0);
    assert(simd.size() == 16);
    std::cout << "  Passed: Base64 SIMD and fallback match" << std::endl;

    std::cout << "[Test] All base64 tests passed!" << std::endl;
    return 0;
}
