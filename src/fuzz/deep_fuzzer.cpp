#include "fuzz_common.hpp"
#include "asset_exerciser.hpp"
#include "telemetry.hpp"
#include "mutation_telemetry.hpp"

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

    // Provenance consumption: consumes pending record once so subsequent replay
    // of the same corpus bytes does not inherit stale attribution.
    fastgltf_fuzz::OperatorId op = fastgltf_fuzz::OperatorId::ByteLibFuzzer;
    fastgltf_fuzz::OperatorFamily fam = fastgltf_fuzz::OperatorFamily::Byte;
    bool hasProvenance = fastgltf_fuzz::MutationTelemetry::instance().consumeProvenance(payload, payloadSize, op, fam);
    fastgltf_fuzz::StageRecorder stageRecorder(op, hasProvenance);

    // GltfDataBuffer lifetime is maintained for the complete testcase duration
    auto bufferExpected = fastgltf::GltfDataBuffer::FromBytes(
        reinterpret_cast<const std::byte*>(payload), payloadSize);
    if (bufferExpected.error() != fastgltf::Error::None) {
        fastgltf_fuzz::Telemetry::instance().recordParseError(bufferExpected.error());
        return 0;
    }

    auto& dataBuffer = bufferExpected.get();

    // Parser lifetime is maintained for the complete testcase duration
    fastgltf::Parser parser(fastgltf::Extensions::None);
    fastgltf::Options options = fastgltf_fuzz::getOptionsForProfile(profile);

    if (fastgltf::hasBit(options, fastgltf::Options::GenerateMeshIndices)) {
        stageRecorder.addFlag(fastgltf_fuzz::STAGE_MESH_INDICES);
    }

    auto assetExpected = parser.loadGltf(dataBuffer, {}, options);

    if (assetExpected.error() != fastgltf::Error::None) {
        fastgltf_fuzz::Telemetry::instance().recordParseError(assetExpected.error());
        return 0;
    }

    stageRecorder.addFlag(fastgltf_fuzz::STAGE_PARSED);

    auto& asset = assetExpected.get();
    fastgltf_fuzz::Telemetry::instance().recordParseSuccess(asset);

    // Explicitly validate asset invariants before exercising accessors.
    auto validationError = fastgltf::validate(asset);
    if (validationError != fastgltf::Error::None) {
        fastgltf_fuzz::Telemetry::instance().recordParseError(validationError);
        return 0;
    }

    stageRecorder.addFlag(fastgltf_fuzz::STAGE_VALIDATED);

    // Deep bounded accessor exercise with Default and Guarded BufferDataAdapters
    fastgltf_fuzz::exerciseAsset(asset);
    stageRecorder.addFlag(fastgltf_fuzz::STAGE_ACCESSOR_EXERCISED);

    return 0;
}
