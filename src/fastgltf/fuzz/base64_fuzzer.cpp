#include <fastgltf/base64.hpp>
#include <fastgltf/core.hpp>
#include <fastgltf/types.hpp>

#include <string_view>
#include <string>
#include <vector>
#include <cstdint>
#include <cstddef>
#include <cstring>
#include <cassert>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < 2) {
        return 0;
    }

    uint8_t mode = Data[0];
    const uint8_t* payload = Data + 1;
    size_t payloadSize = Size - 1;

    // Campaign A: Documented-contract base64 differential testing
    if ((mode & 1) == 0) {
        // Enforce precondition: length >= 4 and length % 4 == 0
        if (payloadSize < 4) {
            return 0;
        }

        size_t alignedSize = payloadSize - (payloadSize % 4);
        if (alignedSize < 4) {
            return 0;
        }

        std::string_view encoded(reinterpret_cast<const char*>(payload), alignedSize);

        try {
            // Compare SIMD-dispatched decode vs portable fallback decode
            auto simdResult = fastgltf::base64::decode(encoded);
            auto fallbackResult = fastgltf::base64::fallback_decode(encoded);

            if (simdResult.size() != fallbackResult.size()) {
                // Differential divergence detected!
                __builtin_trap();
            }

            if (simdResult.size() > 0 &&
                std::memcmp(simdResult.data(), fallbackResult.data(), simdResult.size()) != 0) {
                // Content divergence detected!
                __builtin_trap();
            }

            // Inplace decode test
            std::size_t pad = fastgltf::base64::getPadding(encoded);
            std::size_t outSize = fastgltf::base64::getOutputSize(alignedSize, pad);
            std::vector<uint8_t> inplaceSimd(outSize);
            std::vector<uint8_t> inplaceFallback(outSize);

            fastgltf::base64::decode_inplace(encoded, inplaceSimd.data(), pad);
            fastgltf::base64::fallback_decode_inplace(encoded, inplaceFallback.data(), pad);

            if (std::memcmp(inplaceSimd.data(), inplaceFallback.data(), outSize) != 0) {
                __builtin_trap();
            }
        } catch (...) {
            // Ignore expected invalid base64 exceptions if thrown
        }
    }
    // Campaign B: Public Parser Data URI path with hostile/malformed payloads
    else {
        std::string b64Payload(reinterpret_cast<const char*>(payload), payloadSize);
        std::string json = "{\"asset\":{\"version\":\"2.0\"},\"buffers\":[{\"byteLength\":8,\"uri\":\"data:application/octet-stream;base64," +
                           b64Payload + "\"}]}";

        auto dataBufferExp = fastgltf::GltfDataBuffer::FromBytes(
            reinterpret_cast<const std::byte*>(json.data()), json.size());
        if (dataBufferExp.error() == fastgltf::Error::None) {
            fastgltf::Parser parser(fastgltf::Extensions::None);
            auto res = parser.loadGltf(dataBufferExp.get(), {}, fastgltf::Options::None);
            (void)res;
        }
    }

    return 0;
}
