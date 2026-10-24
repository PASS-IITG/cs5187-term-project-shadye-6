#include "reference_decoder.hpp"
#include <cstring>
#include <cmath>
#include <limits>

namespace fastgltf_fuzz {

namespace {

inline uint16_t readLE16(const uint8_t* p) {
    return static_cast<uint16_t>(p[0]) |
          (static_cast<uint16_t>(p[1]) << 8);
}

inline uint32_t readLE32(const uint8_t* p) {
    return static_cast<uint32_t>(p[0]) |
          (static_cast<uint32_t>(p[1]) << 8) |
          (static_cast<uint32_t>(p[2]) << 16) |
          (static_cast<uint32_t>(p[3]) << 24);
}

inline uint64_t readLE64(const uint8_t* p) {
    return static_cast<uint64_t>(p[0]) |
          (static_cast<uint64_t>(p[1]) << 8) |
          (static_cast<uint64_t>(p[2]) << 16) |
          (static_cast<uint64_t>(p[3]) << 24) |
          (static_cast<uint64_t>(p[4]) << 32) |
          (static_cast<uint64_t>(p[5]) << 40) |
          (static_cast<uint64_t>(p[6]) << 48) |
          (static_cast<uint64_t>(p[7]) << 56);
}

inline float readFloatLE(const uint8_t* p) {
    uint32_t u = readLE32(p);
    float f;
    std::memcpy(&f, &u, sizeof(float));
    return f;
}

const uint8_t* getBufferDataPointer(const fastgltf::Asset& asset, size_t bufferIndex, size_t& outSize) {
    if (bufferIndex >= asset.buffers.size()) {
        return nullptr;
    }
    const auto& buf = asset.buffers[bufferIndex];
    return std::visit(fastgltf::visitor {
        [&](auto&) -> const uint8_t* {
            outSize = 0;
            return nullptr;
        },
        [&](const fastgltf::sources::Fallback&) -> const uint8_t* {
            outSize = 0;
            return nullptr;
        },
        [&](const fastgltf::sources::Array& array) -> const uint8_t* {
            outSize = array.bytes.size_bytes();
            return reinterpret_cast<const uint8_t*>(array.bytes.data());
        },
        [&](const fastgltf::sources::Vector& vec) -> const uint8_t* {
            outSize = vec.bytes.size();
            return reinterpret_cast<const uint8_t*>(vec.bytes.data());
        },
        [&](const fastgltf::sources::ByteView& bv) -> const uint8_t* {
            outSize = bv.bytes.size();
            return reinterpret_cast<const uint8_t*>(bv.bytes.data());
        },
    }, buf.data);
}

} // namespace

std::optional<size_t> ReferenceDecoder::computeRequiredExtent(
        const fastgltf::Asset& asset,
        const fastgltf::Accessor& accessor) {
    if (!accessor.bufferViewIndex.has_value()) {
        return 0; // Accessor without bufferView (e.g. zeros)
    }

    size_t bvIdx = *accessor.bufferViewIndex;
    if (bvIdx >= asset.bufferViews.size()) {
        return std::nullopt;
    }

    if (accessor.count == 0) {
        return 0;
    }

    size_t elemSize = fastgltf::getElementByteSize(accessor.type, accessor.componentType);
    if (elemSize == 0) {
        return std::nullopt;
    }

    const auto& bv = asset.bufferViews[bvIdx];
    size_t stride = bv.byteStride.value_or(elemSize);

    // Checked arithmetic for byteOffset + stride * (count - 1) + elemSize
    size_t countMinusOne = accessor.count - 1;
    if (countMinusOne > 0 && stride > (std::numeric_limits<size_t>::max() / countMinusOne)) {
        return std::nullopt; // Multiplication overflow
    }
    size_t totalSpan = stride * countMinusOne;

    if (std::numeric_limits<size_t>::max() - totalSpan < elemSize) {
        return std::nullopt; // Addition overflow
    }
    totalSpan += elemSize;

    if (std::numeric_limits<size_t>::max() - totalSpan < accessor.byteOffset) {
        return std::nullopt; // Addition overflow
    }
    return accessor.byteOffset + totalSpan;
}

std::optional<float> ReferenceDecoder::decodeScalarFloat(
        const fastgltf::Asset& asset,
        const fastgltf::Accessor& accessor,
        size_t index) {
    if (accessor.type != fastgltf::AccessorType::Scalar) {
        return std::nullopt;
    }
    if (!accessor.bufferViewIndex.has_value() || index >= accessor.count) {
        return std::nullopt;
    }

    size_t bvIdx = *accessor.bufferViewIndex;
    if (bvIdx >= asset.bufferViews.size()) {
        return std::nullopt;
    }
    const auto& bv = asset.bufferViews[bvIdx];

    size_t elemSize = fastgltf::getElementByteSize(accessor.type, accessor.componentType);
    size_t stride = bv.byteStride.value_or(elemSize);

    size_t offset = accessor.byteOffset + index * stride;
    if (offset + elemSize > bv.byteLength) {
        return std::nullopt;
    }

    size_t bufSize = 0;
    const uint8_t* rawBuf = getBufferDataPointer(asset, bv.bufferIndex, bufSize);
    if (!rawBuf || bv.byteOffset + offset + elemSize > bufSize) {
        return std::nullopt;
    }

    const uint8_t* ptr = rawBuf + bv.byteOffset + offset;

    switch (accessor.componentType) {
        case fastgltf::ComponentType::Float:
            return readFloatLE(ptr);
        case fastgltf::ComponentType::Byte: {
            int8_t v = static_cast<int8_t>(*ptr);
            return accessor.normalized ? std::max(v / 127.0f, -1.0f) : static_cast<float>(v);
        }
        case fastgltf::ComponentType::UnsignedByte: {
            uint8_t v = *ptr;
            return accessor.normalized ? v / 255.0f : static_cast<float>(v);
        }
        case fastgltf::ComponentType::Short: {
            int16_t v = static_cast<int16_t>(readLE16(ptr));
            return accessor.normalized ? std::max(v / 32767.0f, -1.0f) : static_cast<float>(v);
        }
        case fastgltf::ComponentType::UnsignedShort: {
            uint16_t v = readLE16(ptr);
            return accessor.normalized ? v / 65535.0f : static_cast<float>(v);
        }
        default:
            return std::nullopt;
    }
}

std::optional<int64_t> ReferenceDecoder::decodeScalarInt(
        const fastgltf::Asset& asset,
        const fastgltf::Accessor& accessor,
        size_t index) {
    if (accessor.type != fastgltf::AccessorType::Scalar) {
        return std::nullopt;
    }
    if (!accessor.bufferViewIndex.has_value() || index >= accessor.count) {
        return std::nullopt;
    }

    size_t bvIdx = *accessor.bufferViewIndex;
    if (bvIdx >= asset.bufferViews.size()) {
        return std::nullopt;
    }
    const auto& bv = asset.bufferViews[bvIdx];

    size_t elemSize = fastgltf::getElementByteSize(accessor.type, accessor.componentType);
    size_t stride = bv.byteStride.value_or(elemSize);

    size_t offset = accessor.byteOffset + index * stride;
    if (offset + elemSize > bv.byteLength) {
        return std::nullopt;
    }

    size_t bufSize = 0;
    const uint8_t* rawBuf = getBufferDataPointer(asset, bv.bufferIndex, bufSize);
    if (!rawBuf || bv.byteOffset + offset + elemSize > bufSize) {
        return std::nullopt;
    }

    const uint8_t* ptr = rawBuf + bv.byteOffset + offset;

    switch (accessor.componentType) {
        case fastgltf::ComponentType::Byte:
            return static_cast<int8_t>(*ptr);
        case fastgltf::ComponentType::UnsignedByte:
            return static_cast<uint8_t>(*ptr);
        case fastgltf::ComponentType::Short:
            return static_cast<int16_t>(readLE16(ptr));
        case fastgltf::ComponentType::UnsignedShort:
            return static_cast<uint16_t>(readLE16(ptr));
        case fastgltf::ComponentType::Int:
            return static_cast<int32_t>(readLE32(ptr));
        case fastgltf::ComponentType::UnsignedInt:
            return static_cast<uint32_t>(readLE32(ptr));
        default:
            return std::nullopt;
    }
}

std::optional<fastgltf::math::fvec3> ReferenceDecoder::decodeVec3Float(
        const fastgltf::Asset& asset,
        const fastgltf::Accessor& accessor,
        size_t index) {
    if (accessor.type != fastgltf::AccessorType::Vec3) {
        return std::nullopt;
    }
    if (!accessor.bufferViewIndex.has_value() || index >= accessor.count) {
        return std::nullopt;
    }

    size_t bvIdx = *accessor.bufferViewIndex;
    if (bvIdx >= asset.bufferViews.size()) {
        return std::nullopt;
    }
    const auto& bv = asset.bufferViews[bvIdx];

    size_t elemSize = fastgltf::getElementByteSize(accessor.type, accessor.componentType);
    size_t stride = bv.byteStride.value_or(elemSize);

    size_t offset = accessor.byteOffset + index * stride;
    if (offset + elemSize > bv.byteLength) {
        return std::nullopt;
    }

    size_t bufSize = 0;
    const uint8_t* rawBuf = getBufferDataPointer(asset, bv.bufferIndex, bufSize);
    if (!rawBuf || bv.byteOffset + offset + elemSize > bufSize) {
        return std::nullopt;
    }

    const uint8_t* ptr = rawBuf + bv.byteOffset + offset;

    if (accessor.componentType == fastgltf::ComponentType::Float) {
        float x = readFloatLE(ptr);
        float y = readFloatLE(ptr + 4);
        float z = readFloatLE(ptr + 8);
        return fastgltf::math::fvec3{x, y, z};
    }

    return std::nullopt;
}

} // namespace fastgltf_fuzz
