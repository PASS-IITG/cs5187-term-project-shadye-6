#pragma once

#include <cstddef>
#include <vector>
#include <unordered_map>
#include <fastgltf/types.hpp>
#include <fastgltf/tools.hpp>

namespace fastgltf_fuzz {

/**
 * GuardedBufferDataAdapter isolates each bufferView into an independent
 * heap allocation with AddressSanitizer redzones on either side.
 *
 * Any out-of-bounds read by fastgltf accessor tools that crosses the declared
 * bufferView boundary will immediately hit an ASan redzone instead of reading
 * valid memory within a shared buffer allocation.
 */
class GuardedBufferDataAdapter {
public:
    GuardedBufferDataAdapter() = default;

    fastgltf::span<const std::byte> operator()(const fastgltf::Asset& asset, std::size_t bufferViewIdx) const;

    void clear();
    bool hadBoundsViolation() const noexcept { return m_hadBoundsViolation; }

private:
    mutable std::unordered_map<std::size_t, std::vector<std::byte>> m_isolatedAllocations;
    mutable bool m_hadBoundsViolation = false;
};

} // namespace fastgltf_fuzz
