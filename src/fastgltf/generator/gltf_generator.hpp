#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>
#include <string>

namespace fastgltf_fuzz {

/**
 * Procedural generator for small, structurally-valid glTF 2.0 and GLB models.
 * Used for generation seeding and hybrid fuzzing arm.
 */
class GltfGenerator {
public:
    static std::string generateJsonGltf(uint32_t seed);
    static std::vector<uint8_t> generateGlb(uint32_t seed);
    static std::string generateSparseJsonGltf(uint32_t seed);
};

} // namespace fastgltf_fuzz
