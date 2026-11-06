#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <fastgltf/types.hpp>

namespace fastgltf_fuzz {

/**
 * Independent reference decoder for glTF accessor data.
 * Adheres directly to glTF 2.0 little-endian decoding rules.
 * Uses checked arithmetic and bounds verification.
 */
class ReferenceDecoder {
public:
    static std::optional<float> decodeScalarFloat(
        const fastgltf::Asset& asset,
        const fastgltf::Accessor& accessor,
        size_t index);

    static std::optional<int64_t> decodeScalarInt(
        const fastgltf::Asset& asset,
        const fastgltf::Accessor& accessor,
        size_t index);

    static std::optional<fastgltf::math::fvec3> decodeVec3Float(
        const fastgltf::Asset& asset,
        const fastgltf::Accessor& accessor,
        size_t index);

    // Calculates required accessor byte extent with checked arithmetic
    // Returns std::nullopt if integer overflow occurs or arithmetic is invalid
    static std::optional<size_t> computeRequiredExtent(
        const fastgltf::Asset& asset,
        const fastgltf::Accessor& accessor);
};

} // namespace fastgltf_fuzz
