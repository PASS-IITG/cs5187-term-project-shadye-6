#pragma once

#include <cstdint>
#include <cstddef>
#include <utility>
#include <string>
#include <cstdio>

namespace fastgltf_fuzz {

// 64-bit FNV-1a non-cryptographic content hash.
// Shared specification with Python campaign manager:
// FNV_OFFSET_BASIS = 14695981039346656037ULL
// FNV_PRIME        = 1099511628211ULL
inline uint64_t fnv1a64(const uint8_t* data, size_t size) {
    constexpr uint64_t FNV_OFFSET_BASIS = 14695981039346656037ULL;
    constexpr uint64_t FNV_PRIME = 1099511628211ULL;
    uint64_t hash = FNV_OFFSET_BASIS;
    for (size_t i = 0; i < size; ++i) {
        hash ^= static_cast<uint64_t>(data[i]);
        hash *= FNV_PRIME;
    }
    return hash;
}

inline std::pair<uint64_t, size_t> computeContentHash(const uint8_t* data, size_t size) {
    return {fnv1a64(data, size), size};
}

inline std::string formatContentHash(uint64_t hash, size_t size) {
    char buf[64];
    std::snprintf(buf, sizeof(buf), "%016llx:%zu", static_cast<unsigned long long>(hash), size);
    return std::string(buf);
}

} // namespace fastgltf_fuzz

