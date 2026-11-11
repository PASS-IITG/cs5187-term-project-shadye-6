#include "guarded_buffer_adapter.hpp"
#include <cstring>
#include <algorithm>

namespace fastgltf_fuzz {

fastgltf::span<const std::byte> GuardedBufferDataAdapter::operator()(
        const fastgltf::Asset& asset, std::size_t bufferViewIdx) const {
    if (bufferViewIdx >= asset.bufferViews.size()) {
        m_hadBoundsViolation = true;
        return {};
    }

    // Return cached allocation if already isolated
    auto it = m_isolatedAllocations.find(bufferViewIdx);
    if (it != m_isolatedAllocations.end()) {
        return fastgltf::span<const std::byte>(it->second.data(), it->second.size());
    }

    const auto& bufferView = asset.bufferViews[bufferViewIdx];
    if (bufferView.bufferIndex >= asset.buffers.size()) {
        m_hadBoundsViolation = true;
        return {};
    }

    // Extract underlying byte span from fastgltf buffer data source
    const auto sourceData = std::visit(fastgltf::visitor {
        [](auto&) -> fastgltf::span<const std::byte> {
            return {};
        },
        [](const fastgltf::sources::Fallback&) -> fastgltf::span<const std::byte> {
            return {};
        },
        [&](const fastgltf::sources::Array& array) -> fastgltf::span<const std::byte> {
            return fastgltf::span(array.bytes.data(), array.bytes.size_bytes());
        },
        [&](const fastgltf::sources::Vector& vec) -> fastgltf::span<const std::byte> {
            return fastgltf::span(vec.bytes.data(), vec.bytes.size());
        },
        [&](const fastgltf::sources::ByteView& bv) -> fastgltf::span<const std::byte> {
            return bv.bytes;
        },
    }, asset.buffers[bufferView.bufferIndex].data);

    if (bufferView.byteLength == 0) {
        // Zero length bufferView
        auto& alloc = m_isolatedAllocations[bufferViewIdx];
        alloc.clear();
        return {};
    }

    size_t sourceSize = sourceData.size();
    if (bufferView.byteOffset >= sourceSize) {
        // BufferView begins past the end of the physical buffer
        m_hadBoundsViolation = true;
        auto& alloc = m_isolatedAllocations[bufferViewIdx];
        alloc.resize(bufferView.byteLength, std::byte{0});
        return fastgltf::span<const std::byte>(alloc.data(), alloc.size());
    }

    size_t available = sourceSize - bufferView.byteOffset;
    size_t copyBytes = std::min(bufferView.byteLength, available);
    if (copyBytes < bufferView.byteLength) {
        m_hadBoundsViolation = true;
    }

    // Allocate isolated memory block of exact declared size
    // Under ASan, this allocation is surrounded by redzones
    std::vector<std::byte> isolated(bufferView.byteLength, std::byte{0});
    if (copyBytes > 0 && sourceData.data() != nullptr) {
        std::memcpy(isolated.data(), sourceData.data() + bufferView.byteOffset, copyBytes);
    }

    auto& stored = m_isolatedAllocations[bufferViewIdx];
    stored = std::move(isolated);
    return fastgltf::span<const std::byte>(stored.data(), stored.size());
}

void GuardedBufferDataAdapter::clear() {
    m_isolatedAllocations.clear();
    m_hadBoundsViolation = false;
}

} // namespace fastgltf_fuzz
