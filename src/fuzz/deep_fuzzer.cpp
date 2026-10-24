#include "fuzz_common.hpp"
#include "asset_exerciser.hpp"
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

    // GltfDataBuffer lifetime is maintained for the complete testcase duration
    auto bufferExpected = fastgltf::GltfDataBuffer::FromBytes(
        reinterpret_cast<const std::byte*>(payload), payloadSize);
    if (bufferExpected.error() != fastgltf::Error::None) {
        fastgltf_fuzz::Telemetry::instance().recordParseError(bufferExpected.error());
        return 0;
    }

    auto& dataBuffer = bufferExpected.get();

    // Parser lifetime is maintained for the complete testcase duration
    // (Parser owns GLB-related buffer states and data source allocations)
    fastgltf::Parser parser(fastgltf::Extensions::None);
    fastgltf::Options options = fastgltf_fuzz::getOptionsForProfile(profile);

    auto assetExpected = parser.loadGltf(dataBuffer, {}, options);

    if (assetExpected.error() != fastgltf::Error::None) {
        fastgltf_fuzz::Telemetry::instance().recordParseError(assetExpected.error());
        return 0;
    }

    auto& asset = assetExpected.get();
    fastgltf_fuzz::Telemetry::instance().recordParseSuccess(asset);

    // Explicitly validate asset invariants before exercising accessors.
    // In fastgltf, loadGltf() performs structural parsing, while validate()
    // verifies accessor indices, bufferView bounds, and buffer alignments.
    // Calling validate() prevents shallow crashes on unvalidated assets and
    // allows the fuzzer to explore deep asset processing continuously.
    auto validationError = fastgltf::validate(asset);
    if (validationError != fastgltf::Error::None) {
        fastgltf_fuzz::Telemetry::instance().recordParseError(validationError);
        return 0;
    }

    // Deep bounded accessor exercise with Default and Guarded BufferDataAdapters
    fastgltf_fuzz::exerciseAsset(asset);

    return 0;
}
