#include "fuzz_common.hpp"
#include "telemetry.hpp"

#include <fastgltf/core.hpp>
#include <cstdint>
#include <cstddef>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < 1) {
        return 0;
    }

    fastgltf_fuzz::Telemetry::instance().recordExecution();

    uint8_t profile = 0;
    const uint8_t* payload = nullptr;
    size_t payloadSize = 0;
    if (!fastgltf_fuzz::splitEnvelope(Data, Size, profile, payload, payloadSize)) {
        return 0;
    }

    if (payloadSize == 0) {
        return 0;
    }

    auto bufferExpected = fastgltf::GltfDataBuffer::FromBytes(
        reinterpret_cast<const std::byte*>(payload), payloadSize);
    if (bufferExpected.error() != fastgltf::Error::None) {
        fastgltf_fuzz::Telemetry::instance().recordParseError(bufferExpected.error());
        return 0;
    }

    auto& dataBuffer = bufferExpected.get();

    // Fresh Parser per testcase for deterministic state
    fastgltf::Parser parser(fastgltf::Extensions::None);
    fastgltf::Options options = fastgltf_fuzz::getOptionsForProfile(profile);

    // Primary in-memory load path with empty directory (no filesystem IO)
    auto assetExpected = parser.loadGltf(dataBuffer, {}, options);

    if (assetExpected.error() != fastgltf::Error::None) {
        fastgltf_fuzz::Telemetry::instance().recordParseError(assetExpected.error());
        return 0;
    }

    fastgltf_fuzz::Telemetry::instance().recordParseSuccess(assetExpected.get());
    return 0;
}
