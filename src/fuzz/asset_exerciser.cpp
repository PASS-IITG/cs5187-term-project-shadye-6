#include "asset_exerciser.hpp"
#include "fuzz_common.hpp"
#include "guarded_buffer_adapter.hpp"
#include "reference_decoder.hpp"
#include "telemetry.hpp"

#include <vector>
#include <algorithm>
#include <cmath>
#include <iostream>

namespace fastgltf_fuzz {

namespace {

// Equality comparison helper supporting scalar, vector, and matrix types
template <typename T>
bool areElementsEqual(const T& a, const T& b) {
    if constexpr (std::is_floating_point_v<T>) {
        if (std::isnan(a) && std::isnan(b)) return true;
        return std::abs(a - b) < 1e-4f;
    } else {
        return a == b;
    }
}

template <>
bool areElementsEqual<fastgltf::math::fvec2>(const fastgltf::math::fvec2& a, const fastgltf::math::fvec2& b) {
    return areElementsEqual(a.x(), b.x()) && areElementsEqual(a.y(), b.y());
}

template <>
bool areElementsEqual<fastgltf::math::fvec3>(const fastgltf::math::fvec3& a, const fastgltf::math::fvec3& b) {
    return areElementsEqual(a.x(), b.x()) && areElementsEqual(a.y(), b.y()) && areElementsEqual(a.z(), b.z());
}

template <>
bool areElementsEqual<fastgltf::math::fvec4>(const fastgltf::math::fvec4& a, const fastgltf::math::fvec4& b) {
    return areElementsEqual(a.x(), b.x()) && areElementsEqual(a.y(), b.y()) &&
           areElementsEqual(a.z(), b.z()) && areElementsEqual(a.w(), b.w());
}

template <>
bool areElementsEqual<fastgltf::math::fmat2x2>(const fastgltf::math::fmat2x2& a, const fastgltf::math::fmat2x2& b) {
    return areElementsEqual(a[0], b[0]) && areElementsEqual(a[1], b[1]);
}

template <>
bool areElementsEqual<fastgltf::math::fmat3x3>(const fastgltf::math::fmat3x3& a, const fastgltf::math::fmat3x3& b) {
    return areElementsEqual(a[0], b[0]) && areElementsEqual(a[1], b[1]) && areElementsEqual(a[2], b[2]);
}

template <>
bool areElementsEqual<fastgltf::math::fmat4x4>(const fastgltf::math::fmat4x4& a, const fastgltf::math::fmat4x4& b) {
    return areElementsEqual(a[0], b[0]) && areElementsEqual(a[1], b[1]) &&
           areElementsEqual(a[2], b[2]) && areElementsEqual(a[3], b[3]);
}

template <typename ElementType, typename Adapter>
void testAccessorWithAdapter(const fastgltf::Asset& asset,
                             const fastgltf::Accessor& accessor,
                             const Adapter& adapter) {
    if (accessor.count == 0) {
        return;
    }

    Telemetry::instance().recordAccessorExercised(accessor.sparse.has_value());

    // 1. Compute bounded sample indices
    std::vector<size_t> sampleIndices;
    size_t count = accessor.count;
    size_t maxSamples = std::min(count, MAX_ELEMENTS_PER_ACCESSOR);

    for (size_t i = 0; i < std::min(count, size_t(16)); ++i) {
        sampleIndices.push_back(i);
    }
    if (count > 32) {
        sampleIndices.push_back(count / 4);
        sampleIndices.push_back(count / 2);
        sampleIndices.push_back((3 * count) / 4);
    }
    for (size_t i = (count > 8 ? count - 8 : 0); i < count; ++i) {
        if (std::find(sampleIndices.begin(), sampleIndices.end(), i) == sampleIndices.end()) {
            sampleIndices.push_back(i);
        }
    }
    std::sort(sampleIndices.begin(), sampleIndices.end());
    if (sampleIndices.size() > maxSamples) {
        sampleIndices.resize(maxSamples);
    }

    // 2. getAccessorElement for each sampled index
    std::vector<ElementType> sampledValues;
    sampledValues.reserve(sampleIndices.size());
    for (size_t idx : sampleIndices) {
        sampledValues.push_back(fastgltf::getAccessorElement<ElementType>(asset, accessor, idx, adapter));
    }

    // 3. iterateAccessor & iterateAccessorWithIndex
    size_t iterCount = 0;
    size_t sampleSearchIdx = 0;
    fastgltf::iterateAccessorWithIndex<ElementType>(asset, accessor, [&](auto&& val, size_t idx) {
        if (sampleSearchIdx < sampleIndices.size() && idx == sampleIndices[sampleSearchIdx]) {
            if (!areElementsEqual(val, sampledValues[sampleSearchIdx])) {
                Telemetry::instance().recordMetamorphicMismatch();
            }
            ++sampleSearchIdx;
        }
        ++iterCount;
    }, adapter);

    // 4. copyFromAccessor for small bounded counts
    if (count <= MAX_ELEMENTS_PER_ACCESSOR) {
        std::vector<ElementType> copiedData(count);
        fastgltf::copyFromAccessor<ElementType>(asset, accessor, copiedData.data(), adapter);

        for (size_t i = 0; i < sampleIndices.size(); ++i) {
            size_t idx = sampleIndices[i];
            if (idx < copiedData.size()) {
                if (!areElementsEqual(copiedData[idx], sampledValues[i])) {
                    Telemetry::instance().recordMetamorphicMismatch();
                }
            }
        }
    }
}

template <typename ElementType>
void exerciseCompatibleAccessor(const fastgltf::Asset& asset, const fastgltf::Accessor& accessor) {
    // A) Exercise with DefaultBufferDataAdapter
    fastgltf::DefaultBufferDataAdapter defaultAdapter;
    testAccessorWithAdapter<ElementType>(asset, accessor, defaultAdapter);

    // B) Exercise with GuardedBufferDataAdapter (ASan redzones)
    GuardedBufferDataAdapter guardedAdapter;
    testAccessorWithAdapter<ElementType>(asset, accessor, guardedAdapter);
}

bool isBufferLoaded(const fastgltf::Asset& asset, size_t bufferIndex) {
    if (bufferIndex >= asset.buffers.size()) {
        return false;
    }
    return std::visit(fastgltf::visitor {
        [](const fastgltf::sources::Array&) { return true; },
        [](const fastgltf::sources::Vector&) { return true; },
        [](const fastgltf::sources::ByteView&) { return true; },
        [](const fastgltf::sources::CustomBuffer&) { return true; },
        [](const auto&) { return false; }
    }, asset.buffers[bufferIndex].data);
}

bool isBufferViewLoaded(const fastgltf::Asset& asset, size_t bufferViewIndex) {
    if (bufferViewIndex >= asset.bufferViews.size()) {
        return false;
    }
    return isBufferLoaded(asset, asset.bufferViews[bufferViewIndex].bufferIndex);
}

void dispatchAccessor(const fastgltf::Asset& asset, const fastgltf::Accessor& accessor) {
    // Precondition check: must have valid AccessorType and ComponentType
    if (accessor.type == fastgltf::AccessorType::Invalid ||
        accessor.componentType == fastgltf::ComponentType::Invalid) {
        return;
    }

    // Precondition check: bufferViewIndex must be valid if specified, and buffer data must be loaded
    if (accessor.bufferViewIndex.has_value()) {
        if (*accessor.bufferViewIndex >= asset.bufferViews.size()) {
            Telemetry::instance().recordExtentViolation();
            return;
        }
        if (!isBufferViewLoaded(asset, *accessor.bufferViewIndex)) {
            return;
        }
    }

    // Precondition check: sparse bufferViews must be valid if specified, and buffer data must be loaded
    if (accessor.sparse.has_value()) {
        if (accessor.sparse->indicesBufferView >= asset.bufferViews.size() ||
            accessor.sparse->valuesBufferView >= asset.bufferViews.size()) {
            Telemetry::instance().recordExtentViolation();
            return;
        }
        if (!isBufferViewLoaded(asset, accessor.sparse->indicesBufferView) ||
            !isBufferViewLoaded(asset, accessor.sparse->valuesBufferView)) {
            return;
        }
    }

    // Check independent extent oracle
    auto extentOpt = ReferenceDecoder::computeRequiredExtent(asset, accessor);
    if (!extentOpt.has_value()) {
        Telemetry::instance().recordExtentViolation();
    } else if (accessor.bufferViewIndex.has_value()) {
        const auto& bv = asset.bufferViews[*accessor.bufferViewIndex];
        if (*extentOpt > bv.byteLength) {
            Telemetry::instance().recordExtentViolation();
        }
    }

    // Dispatch strictly to compatible ElementType to respect fastgltf assertion contract
    switch (accessor.type) {
        case fastgltf::AccessorType::Scalar: {
            switch (accessor.componentType) {
                case fastgltf::ComponentType::Float:
                    exerciseCompatibleAccessor<float>(asset, accessor);
                    break;
                case fastgltf::ComponentType::Double:
                    exerciseCompatibleAccessor<double>(asset, accessor);
                    break;
                case fastgltf::ComponentType::Byte:
                    exerciseCompatibleAccessor<int8_t>(asset, accessor);
                    break;
                case fastgltf::ComponentType::UnsignedByte:
                    exerciseCompatibleAccessor<uint8_t>(asset, accessor);
                    break;
                case fastgltf::ComponentType::Short:
                    exerciseCompatibleAccessor<int16_t>(asset, accessor);
                    break;
                case fastgltf::ComponentType::UnsignedShort:
                    exerciseCompatibleAccessor<uint16_t>(asset, accessor);
                    break;
                case fastgltf::ComponentType::Int:
                    exerciseCompatibleAccessor<int32_t>(asset, accessor);
                    break;
                case fastgltf::ComponentType::UnsignedInt:
                    exerciseCompatibleAccessor<uint32_t>(asset, accessor);
                    break;
                default:
                    break;
            }
            break;
        }
        case fastgltf::AccessorType::Vec2:
            exerciseCompatibleAccessor<fastgltf::math::fvec2>(asset, accessor);
            break;
        case fastgltf::AccessorType::Vec3:
            exerciseCompatibleAccessor<fastgltf::math::fvec3>(asset, accessor);
            break;
        case fastgltf::AccessorType::Vec4:
            exerciseCompatibleAccessor<fastgltf::math::fvec4>(asset, accessor);
            break;
        case fastgltf::AccessorType::Mat2:
            exerciseCompatibleAccessor<fastgltf::math::fmat2x2>(asset, accessor);
            break;
        case fastgltf::AccessorType::Mat3:
            exerciseCompatibleAccessor<fastgltf::math::fmat3x3>(asset, accessor);
            break;
        case fastgltf::AccessorType::Mat4:
            exerciseCompatibleAccessor<fastgltf::math::fmat4x4>(asset, accessor);
            break;
        default:
            break;
    }
}

} // namespace

void exerciseAsset(const fastgltf::Asset& asset) {
    size_t totalObjects = asset.nodes.size() + asset.meshes.size() +
                          asset.materials.size() + asset.textures.size() +
                          asset.accessors.size() + asset.bufferViews.size();
    if (totalObjects > MAX_OBJECTS_VISITED) {
        // Enforce upper bound on scene complexity
        totalObjects = MAX_OBJECTS_VISITED;
    }

    size_t accessorsToExercise = std::min(asset.accessors.size(), MAX_ACCESSORS_EXERCISED);
    for (size_t i = 0; i < accessorsToExercise; ++i) {
        dispatchAccessor(asset, asset.accessors[i]);
    }
}

} // namespace fastgltf_fuzz
