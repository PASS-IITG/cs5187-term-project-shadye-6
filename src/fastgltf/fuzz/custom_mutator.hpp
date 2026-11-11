#pragma once

#include <cstddef>
#include <cstdint>

namespace fastgltf_fuzz {

enum class FuzzMode {
    Byte,
    Struct,
    Hybrid
};

FuzzMode getFuzzMode();

// Internal core mutator function for unit testing and libFuzzer integration
size_t mutatePayload(uint8_t* data, size_t size, size_t maxSize, unsigned int seed, FuzzMode mode);

} // namespace fastgltf_fuzz

extern "C" {
size_t LLVMFuzzerCustomMutator(uint8_t *Data, size_t Size, size_t MaxSize, unsigned int Seed);
size_t LLVMFuzzerMutate(uint8_t *Data, size_t Size, size_t MaxSize);
}
