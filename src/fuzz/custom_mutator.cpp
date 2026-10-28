#include "custom_mutator.hpp"
#include "fuzz_common.hpp"
#include "glb_parser.hpp"
#include "mutation_scheduler.hpp"
#include "mutation_telemetry.hpp"
#include "../generator/gltf_generator.hpp"

#include <nlohmann/json.hpp>
#include <random>
#include <vector>
#include <string>
#include <cstring>
#include <cstdlib>
#include <algorithm>

namespace fastgltf_fuzz {

// Weak fallback definition of LLVMFuzzerMutate so standalone unit tests can link
// without requiring the libFuzzer runtime engine.
extern "C" __attribute__((weak)) size_t LLVMFuzzerMutate(uint8_t *Data, size_t Size, size_t MaxSize) {
    if (Size == 0 || MaxSize == 0) return 0;
    Data[0] ^= 0x55;
    return Size;
}

FuzzMode getFuzzMode() {
    const char* env = std::getenv("FUZZ_MODE");
    if (!env) {
        return FuzzMode::Hybrid; // Default mode
    }
    std::string s(env);
    if (s == "byte") return FuzzMode::Byte;
    if (s == "struct") return FuzzMode::Struct;
    return FuzzMode::Hybrid;
}

namespace {

// Boundary integers commonly triggering off-by-one or overflow errors
const std::vector<uint64_t> BOUNDARY_INTS = {
    0, 1, 2, 3, 4, 7, 8, 15, 16, 31, 32, 63, 64, 127, 128, 255, 256,
    511, 512, 1023, 1024, 2048, 4096, 65535, 65536,
    0x7FFFFFFFULL, 0x80000000ULL, 0xFFFFFFFFULL,
    0xFFFFFFFEULL, 0xFFFFFFFFFFFFFFFFULL
};

uint64_t mutateBoundary(uint64_t current, std::mt19937& rng) {
    uint32_t choice = rng() % 5;
    if (choice == 0 && current > 0) return current - 1;
    if (choice == 1) return current + 1;
    if (choice == 2) return current * 2;
    if (choice == 3) return current / 2;
    return BOUNDARY_INTS[rng() % BOUNDARY_INTS.size()];
}

void mutateJsonAst(nlohmann::json& j, std::mt19937& rng, bool repair) {
    uint32_t action = rng() % 7;

    // Action 0: Mutate Buffers (byteLength, uri)
    if (action == 0 && j.contains("buffers") && j["buffers"].is_array() && !j["buffers"].empty()) {
        auto& buf = j["buffers"][rng() % j["buffers"].size()];
        if (buf.is_object()) {
            if (buf.contains("byteLength") && buf["byteLength"].is_number()) {
                uint64_t len = buf["byteLength"].get<uint64_t>();
                buf["byteLength"] = mutateBoundary(len, rng);
            }
            if (buf.contains("uri") && buf["uri"].is_string()) {
                static const std::vector<std::string> URI_PAYLOADS = {
                    "%", "%A", "%0", "%00", "%2G", "%GG", "%%A",
                    "data:application/octet-stream;base64,%",
                    "data:application/octet-stream;base64,%A",
                    "data:application/octet-stream;base64,A==",
                    "data:application/octet-stream;base64,===",
                    "data:application/octet-stream;base64,",
                    "data:image/png;base64,AAAA"
                };
                buf["uri"] = URI_PAYLOADS[rng() % URI_PAYLOADS.size()];
            }
        }
    }
    // Action 1: Mutate BufferViews (byteOffset, byteLength, byteStride)
    else if (action == 1 && j.contains("bufferViews") && j["bufferViews"].is_array() && !j["bufferViews"].empty()) {
        auto& bv = j["bufferViews"][rng() % j["bufferViews"].size()];
        if (bv.is_object()) {
            uint32_t sub = rng() % 4;
            if (sub == 0 && bv.contains("byteOffset") && bv["byteOffset"].is_number()) {
                bv["byteOffset"] = mutateBoundary(bv["byteOffset"].get<uint64_t>(), rng);
            } else if (sub == 1 && bv.contains("byteLength") && bv["byteLength"].is_number()) {
                bv["byteLength"] = mutateBoundary(bv["byteLength"].get<uint64_t>(), rng);
            } else if (sub == 2) {
                static const std::vector<uint32_t> STRIDES = { 0, 1, 2, 3, 4, 8, 12, 16, 252, 256, 1024 };
                bv["byteStride"] = STRIDES[rng() % STRIDES.size()];
            } else if (sub == 3 && bv.contains("buffer") && bv["buffer"].is_number()) {
                bv["buffer"] = mutateBoundary(bv["buffer"].get<uint64_t>(), rng);
            }
        }
    }
    // Action 2: Mutate Accessors (count, byteOffset, componentType, type)
    else if (action == 2 && j.contains("accessors") && j["accessors"].is_array() && !j["accessors"].empty()) {
        auto& acc = j["accessors"][rng() % j["accessors"].size()];
        if (acc.is_object()) {
            uint32_t sub = rng() % 5;
            if (sub == 0 && acc.contains("count") && acc["count"].is_number()) {
                acc["count"] = mutateBoundary(acc["count"].get<uint64_t>(), rng);
            } else if (sub == 1 && acc.contains("byteOffset") && acc["byteOffset"].is_number()) {
                acc["byteOffset"] = mutateBoundary(acc["byteOffset"].get<uint64_t>(), rng);
            } else if (sub == 2 && acc.contains("componentType") && acc["componentType"].is_number()) {
                static const std::vector<uint32_t> COMPONENT_TYPES = {
                    0, 5120, 5121, 5122, 5123, 5125, 5126, 5124, 5127, 65535
                };
                acc["componentType"] = COMPONENT_TYPES[rng() % COMPONENT_TYPES.size()];
            } else if (sub == 3 && acc.contains("type") && acc["type"].is_string()) {
                static const std::vector<std::string> TYPES = {
                    "SCALAR", "VEC2", "VEC3", "VEC4", "MAT2", "MAT3", "MAT4", "INVALID_TYPE", ""
                };
                acc["type"] = TYPES[rng() % TYPES.size()];
            } else if (sub == 4 && acc.contains("bufferView") && acc["bufferView"].is_number()) {
                acc["bufferView"] = mutateBoundary(acc["bufferView"].get<uint64_t>(), rng);
            }
        }
    }
    // Action 3: Mutate Sparse Accessors
    else if (action == 3 && j.contains("accessors") && j["accessors"].is_array() && !j["accessors"].empty()) {
        auto& acc = j["accessors"][rng() % j["accessors"].size()];
        if (acc.is_object()) {
            if (!acc.contains("sparse")) {
                nlohmann::json sparse;
                sparse["count"] = (rng() % 10) + 1;
                sparse["indices"] = {{"bufferView", 0}, {"byteOffset", 0}, {"componentType", 5123}};
                sparse["values"] = {{"bufferView", 0}, {"byteOffset", 0}};
                acc["sparse"] = sparse;
            } else {
                auto& sparse = acc["sparse"];
                if (sparse.contains("count")) {
                    sparse["count"] = mutateBoundary(sparse["count"].get<uint64_t>(), rng);
                }
            }
        }
    }
    // Action 4: Mutate Mesh Primitives & POSITION attribute (triggers F011)
    else if (action == 4 && j.contains("meshes") && j["meshes"].is_array() && !j["meshes"].empty()) {
        auto& mesh = j["meshes"][rng() % j["meshes"].size()];
        if (mesh.is_object() && mesh.contains("primitives") && mesh["primitives"].is_array() && !mesh["primitives"].empty()) {
            auto& prim = mesh["primitives"][rng() % mesh["primitives"].size()];
            if (prim.is_object()) {
                uint32_t sub = rng() % 3;
                if (sub == 0) {
                    if (!prim.contains("attributes")) prim["attributes"] = nlohmann::json::object();
                    prim["attributes"]["POSITION"] = mutateBoundary(5, rng);
                } else if (sub == 1 && prim.contains("indices")) {
                    prim["indices"] = mutateBoundary(prim["indices"].get<uint64_t>(), rng);
                } else {
                    static const std::vector<uint32_t> MODES = { 0, 1, 2, 3, 4, 5, 6, 7, 255 };
                    prim["mode"] = MODES[rng() % MODES.size()];
                }
            }
        }
    }
    // Action 5: Structural Repair (if repair=true)
    if (repair) {
        if (j.contains("buffers") && j["buffers"].is_array() && j.contains("bufferViews") && j["bufferViews"].is_array()) {
            uint64_t maxBvEnd = 0;
            for (auto& bv : j["bufferViews"]) {
                if (bv.is_object() && bv.contains("byteOffset") && bv.contains("byteLength")) {
                    uint64_t end = bv["byteOffset"].get<uint64_t>() + bv["byteLength"].get<uint64_t>();
                    if (end > maxBvEnd) maxBvEnd = end;
                }
            }
            if (!j["buffers"].empty() && j["buffers"][0].is_object()) {
                if (j["buffers"][0].contains("byteLength")) {
                    uint64_t curLen = j["buffers"][0]["byteLength"].get<uint64_t>();
                    if (curLen < maxBvEnd) {
                        j["buffers"][0]["byteLength"] = maxBvEnd;
                    }
                }
            }
        }
    }
}

std::string mutateJsonTextual(std::string text, std::mt19937& rng) {
    uint32_t action = rng() % 5;
    if (action == 0) {
        size_t pos = text.find("\"byteLength\":");
        if (pos != std::string::npos) {
            pos += 13;
            text.insert(pos, "99999999999999999999");
        }
    } else if (action == 1) {
        static const std::vector<std::string> NUMBERS = {
            "1e99999", "-1e99999", "1e-99999", "-0.0", "NaN", "Infinity", "0.00000000000000000000001"
        };
        size_t pos = text.find("5126");
        if (pos != std::string::npos) {
            text.replace(pos, 4, NUMBERS[rng() % NUMBERS.size()]);
        }
    } else if (action == 2) {
        if (text.size() > 5) {
            size_t idx = rng() % text.size();
            text[idx] = (rng() % 2 == 0) ? '{' : '}';
        }
    } else if (action == 3) {
        size_t cut = (rng() % 8) + 1;
        if (text.size() > cut) {
            text.resize(text.size() - cut);
        }
    } else {
        size_t pos = text.find("\"uri\"");
        if (pos != std::string::npos) {
            text.insert(pos + 7, "%25%00%A");
        }
    }
    return text;
}

void mutateGlbContainer(GlbContainer& glb, std::mt19937& rng, bool repair) {
    uint32_t action = rng() % 5;
    if (action == 0) {
        uint32_t sub = rng() % 3;
        if (sub == 0) glb.magic = (rng() % 2 == 0) ? 0x12345678 : 0x00000000;
        else if (sub == 1) glb.version = (rng() % 4);
        else glb.declaredTotalLength = mutateBoundary(glb.declaredTotalLength, rng);
    } else if (action == 1 && !glb.chunks.empty()) {
        for (auto& chunk : glb.chunks) {
            if (chunk.chunkType == GLB_CHUNK_JSON && !chunk.data.empty()) {
                std::string jsonStr(chunk.data.begin(), chunk.data.end());
                try {
                    auto j = nlohmann::json::parse(jsonStr);
                    mutateJsonAst(j, rng, repair);
                    std::string res = j.dump();
                    chunk.data.assign(res.begin(), res.end());
                } catch (...) {
                    jsonStr = mutateJsonTextual(jsonStr, rng);
                    chunk.data.assign(jsonStr.begin(), jsonStr.end());
                }
                break;
            }
        }
    } else if (action == 2 && !glb.chunks.empty()) {
        for (auto& chunk : glb.chunks) {
            if (chunk.chunkType == GLB_CHUNK_BIN && !chunk.data.empty()) {
                size_t sz = chunk.data.size();
                uint32_t sub = rng() % 3;
                if (sub == 0 && sz > 4) {
                    chunk.data.resize(sz / 2);
                } else if (sub == 1) {
                    chunk.data.resize(sz + 16, 0xFF);
                } else {
                    chunk.chunkLength = mutateBoundary(chunk.chunkLength, rng);
                }
                break;
            }
        }
    } else if (action == 3) {
        if (glb.chunks.size() >= 2) {
            std::swap(glb.chunks[0], glb.chunks[1]);
        }
    } else {
        GlbChunk newChunk;
        newChunk.chunkType = 0xDEADBEEF;
        newChunk.chunkLength = 16;
        newChunk.data.resize(16, 0x42);
        glb.chunks.push_back(std::move(newChunk));
    }
}

void ensurePolicyLoaded() {
    static bool s_loaded = false;
    if (!s_loaded) {
        s_loaded = true;
        const char* polEnv = std::getenv("FUZZ_POLICY_FILE");
        if (polEnv && polEnv[0] != '\0') {
            DiscountedUcbScheduler::instance().loadPolicySnapshot(polEnv);
            DiscountedUcbScheduler::instance().setActive(true);
        }
    }
}

} // namespace

size_t mutatePayload(uint8_t* data, size_t size, size_t maxSize, unsigned int seed, FuzzMode mode) {
    if (size < 1 || maxSize < 2) {
        return size;
    }

    ensurePolicyLoaded();

    std::mt19937 rng(seed);

    // Envelope: byte 0 is profile byte, rest is payload
    uint8_t profile = data[0];
    if ((rng() % 10) == 0) {
        profile = static_cast<uint8_t>(rng() % static_cast<uint8_t>(ConfigProfile::NumProfiles));
    }

    uint8_t* payload = data + 1;
    size_t payloadSize = size - 1;
    size_t maxPayloadSize = maxSize - 1;

    OperatorId chosenOp = OperatorId::ByteLibFuzzer;
    OperatorFamily chosenFam = OperatorFamily::Byte;

    // Check if adaptive policy is active
    bool isAdaptive = (mode == FuzzMode::Hybrid) && DiscountedUcbScheduler::instance().isAdaptiveActive();

    if (isAdaptive) {
        chosenOp = DiscountedUcbScheduler::instance().selectOperator(rng);
        chosenFam = DiscountedUcbScheduler::instance().getOperatorInfo(chosenOp).family;
    } else if (mode == FuzzMode::Byte) {
        chosenOp = OperatorId::ByteLibFuzzer;
        chosenFam = OperatorFamily::Byte;
    } else if (mode == FuzzMode::Struct) {
        chosenFam = OperatorFamily::StructuredValid;
        chosenOp = (rng() % 2 == 0) ? OperatorId::StructGlbRepair : OperatorId::StructJsonAstRepair;
    } else {
        // Hybrid baseline fixed weights: 25/25/40/10
        uint32_t roll = rng() % 100;
        if (roll < 25) {
            chosenFam = OperatorFamily::Byte;
            chosenOp = OperatorId::ByteLibFuzzer;
        } else if (roll < 50) {
            chosenFam = OperatorFamily::StructuredValid;
            chosenOp = (rng() % 2 == 0) ? OperatorId::StructGlbRepair : OperatorId::StructJsonAstRepair;
        } else if (roll < 90) {
            chosenFam = OperatorFamily::InvariantBreaking;
            uint32_t sub = rng() % 3;
            if (sub == 0) chosenOp = OperatorId::StructGlbCorrupt;
            else if (sub == 1) chosenOp = OperatorId::StructJsonAstCorrupt;
            else chosenOp = OperatorId::StructJsonTextual;
        } else {
            chosenFam = OperatorFamily::Procedural;
            chosenOp = OperatorId::ProceduralGenerator;
        }
    }

    size_t newPayloadSize = payloadSize;

    // Dispatch mutation according to chosen operator
    switch (chosenOp) {
        case OperatorId::ByteLibFuzzer: {
            newPayloadSize = LLVMFuzzerMutate(payload, payloadSize, maxPayloadSize);
            break;
        }

        case OperatorId::ProceduralGenerator: {
            std::vector<uint8_t> genBytes;
            if (rng() % 2 == 0) {
                genBytes = GltfGenerator::generateGlb(seed);
            } else {
                std::string s = (rng() % 2 == 0) ? GltfGenerator::generateJsonGltf(seed)
                                                : GltfGenerator::generateSparseJsonGltf(seed);
                genBytes.assign(s.begin(), s.end());
            }
            if (genBytes.size() <= maxPayloadSize && !genBytes.empty()) {
                std::memcpy(payload, genBytes.data(), genBytes.size());
                newPayloadSize = genBytes.size();
            } else {
                newPayloadSize = LLVMFuzzerMutate(payload, payloadSize, maxPayloadSize);
            }
            break;
        }

        case OperatorId::StructGlbRepair:
        case OperatorId::StructGlbCorrupt: {
            bool repair = (chosenOp == OperatorId::StructGlbRepair);
            if (GlbParser::isGlb(payload, payloadSize)) {
                GlbContainer container;
                if (GlbParser::parse(payload, payloadSize, container)) {
                    mutateGlbContainer(container, rng, repair);
                    auto serialized = GlbParser::serialize(container, repair);
                    if (serialized.size() <= maxPayloadSize && !serialized.empty()) {
                        std::memcpy(payload, serialized.data(), serialized.size());
                        newPayloadSize = serialized.size();
                        break;
                    }
                }
            }
            // Fallback to byte mutation if not valid GLB
            newPayloadSize = LLVMFuzzerMutate(payload, payloadSize, maxPayloadSize);
            break;
        }

        case OperatorId::StructJsonAstRepair:
        case OperatorId::StructJsonAstCorrupt: {
            bool repair = (chosenOp == OperatorId::StructJsonAstRepair);
            std::string jsonStr(reinterpret_cast<const char*>(payload), payloadSize);
            try {
                auto j = nlohmann::json::parse(jsonStr);
                mutateJsonAst(j, rng, repair);
                std::string mutated = j.dump();
                if (mutated.size() <= maxPayloadSize) {
                    std::memcpy(payload, mutated.data(), mutated.size());
                    newPayloadSize = mutated.size();
                    break;
                }
            } catch (...) {
                // If DOM parse failed, fallback to textual mutation
                std::string mutated = mutateJsonTextual(jsonStr, rng);
                if (mutated.size() <= maxPayloadSize) {
                    std::memcpy(payload, mutated.data(), mutated.size());
                    newPayloadSize = mutated.size();
                    break;
                }
            }
            newPayloadSize = LLVMFuzzerMutate(payload, payloadSize, maxPayloadSize);
            break;
        }

        case OperatorId::StructJsonTextual: {
            std::string jsonStr(reinterpret_cast<const char*>(payload), payloadSize);
            std::string mutated = mutateJsonTextual(jsonStr, rng);
            if (mutated.size() <= maxPayloadSize) {
                std::memcpy(payload, mutated.data(), mutated.size());
                newPayloadSize = mutated.size();
            } else {
                newPayloadSize = LLVMFuzzerMutate(payload, payloadSize, maxPayloadSize);
            }
            break;
        }

        default: {
            newPayloadSize = LLVMFuzzerMutate(payload, payloadSize, maxPayloadSize);
            break;
        }
    }

    // Set profile byte in envelope
    data[0] = profile;

    // Record provenance of emitted mutated bytes in telemetry
    MutationTelemetry::instance().recordMutationEmitted(payload, newPayloadSize, chosenOp, chosenFam);

    return 1 + newPayloadSize;
}

} // namespace fastgltf_fuzz

extern "C" size_t LLVMFuzzerCustomMutator(uint8_t *Data, size_t Size, size_t MaxSize, unsigned int Seed) {
    fastgltf_fuzz::FuzzMode mode = fastgltf_fuzz::getFuzzMode();
    return fastgltf_fuzz::mutatePayload(Data, Size, MaxSize, Seed, mode);
}
