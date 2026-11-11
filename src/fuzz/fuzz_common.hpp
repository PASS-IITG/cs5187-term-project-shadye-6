#pragma once

#include <cstddef>
#include <cstdint>
#include <fastgltf/core.hpp>
#include <fastgltf/types.hpp>

namespace fastgltf_fuzz {

// Maximum bounds for bounded deep traversal
constexpr size_t MAX_ACCESSORS_EXERCISED   = 100;
constexpr size_t MAX_ELEMENTS_PER_ACCESSOR = 64;
constexpr size_t MAX_OBJECTS_VISITED       = 1000;

// Configuration profiles selected by the envelope's first byte
enum class ConfigProfile : uint8_t {
    ProfileNone                      = 0,
    ProfileAllowDouble               = 1,
    ProfileDecomposeNodeMatrices     = 2,
    ProfileGenerateMeshIndices       = 3,
    ProfileDontRequireValidAsset     = 4,
    ProfileDoubleAndMeshIndices      = 5,
    ProfileDoubleDecomposeAndIndices = 6,
    ProfileDontRequireAndIndices     = 7,
    NumProfiles                      = 8
};

// Maps a raw selector byte to an explicitly chosen v0.9.1 Options mask
inline fastgltf::Options getOptionsForProfile(uint8_t selectorByte) {
    auto profile = static_cast<ConfigProfile>(selectorByte % static_cast<uint8_t>(ConfigProfile::NumProfiles));
    switch (profile) {
        case ConfigProfile::ProfileNone:
            return fastgltf::Options::None;
        case ConfigProfile::ProfileAllowDouble:
            return fastgltf::Options::AllowDouble;
        case ConfigProfile::ProfileDecomposeNodeMatrices:
            return fastgltf::Options::DecomposeNodeMatrices;
        case ConfigProfile::ProfileGenerateMeshIndices:
            return fastgltf::Options::GenerateMeshIndices;
        case ConfigProfile::ProfileDontRequireValidAsset:
            return fastgltf::Options::DontRequireValidAssetMember;
        case ConfigProfile::ProfileDoubleAndMeshIndices:
            return fastgltf::Options::AllowDouble | fastgltf::Options::GenerateMeshIndices;
        case ConfigProfile::ProfileDoubleDecomposeAndIndices:
            return fastgltf::Options::AllowDouble |
                   fastgltf::Options::DecomposeNodeMatrices |
                   fastgltf::Options::GenerateMeshIndices;
        case ConfigProfile::ProfileDontRequireAndIndices:
            return fastgltf::Options::DontRequireValidAssetMember |
                   fastgltf::Options::GenerateMeshIndices;
        default:
            return fastgltf::Options::None;
    }
}

// Splits the fuzzer envelope [config_byte][payload...]
inline bool splitEnvelope(const uint8_t* data, size_t size,
                          uint8_t& outProfile,
                          const uint8_t*& outPayload, size_t& outPayloadSize) {
    if (size < 1) {
        return false;
    }
    outProfile = data[0];
    outPayload = data + 1;
    outPayloadSize = size - 1;
    return true;
}

} // namespace fastgltf_fuzz
