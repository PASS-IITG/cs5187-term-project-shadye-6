#include "custom_mutator.hpp"
#include "fuzz_common.hpp"
#include "glb_parser.hpp"
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
                // Mutate URI with percent-encoding patterns
                std::string uri = buf["uri"].get<std::string>();
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
                // Mutate or add byteStride (glTF requires stride between 4 and 252, multiple of 4)
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
            } else if (sub == 2) {
                // Component types: 5120(byte), 5121(ubyte), 5122(short), 5123(ushort), 5125(uint), 5126(float), 5130(double)
                static const std::vector<uint32_t> COMPONENT_TYPES = {
                    5120, 5121, 5122, 5123, 5124, 5125, 5126, 5130, 0, 9999
                };
                acc["componentType"] = COMPONENT_TYPES[rng() % COMPONENT_TYPES.size()];
            } else if (sub == 3) {
                static const std::vector<std::string> ACCESSOR_TYPES = {
                    "SCALAR", "VEC2", "VEC3", "VEC4", "MAT2", "MAT3", "MAT4", "INVALID"
                };
                acc["type"] = ACCESSOR_TYPES[rng() % ACCESSOR_TYPES.size()];
            } else if (sub == 4 && acc.contains("bufferView") && acc["bufferView"].is_number()) {
                acc["bufferView"] = mutateBoundary(acc["bufferView"].get<uint64_t>(), rng);
            }
        }
    }
    // Action 3: Mutate Sparse Accessors
    else if (action == 3 && j.contains("accessors") && j["accessors"].is_array() && !j["accessors"].empty()) {
        auto& acc = j["accessors"][rng() % j["accessors"].size()];
        if (acc.is_object()) {
            if (acc.contains("sparse") && acc["sparse"].is_object()) {
                auto& sparse = acc["sparse"];
                if (sparse.contains("count") && sparse["count"].is_number()) {
                    sparse["count"] = mutateBoundary(sparse["count"].get<uint64_t>(), rng);
                }
            } else {
                // Add sparse accessor
                nlohmann::json sparse;
                sparse["count"] = (rng() % 4) + 1;
                sparse["indices"] = {{"bufferView", 0}, {"byteOffset", 0}, {"componentType", 5123}};
                sparse["values"] = {{"bufferView", 0}, {"byteOffset", 0}};
                acc["sparse"] = sparse;
            }
        }
    }
    // Action 4: Mutate Mesh Primitives (indices, attributes)
    else if (action == 4 && j.contains("meshes") && j["meshes"].is_array() && !j["meshes"].empty()) {
        auto& mesh = j["meshes"][rng() % j["meshes"].size()];
        if (mesh.is_object() && mesh.contains("primitives") && mesh["primitives"].is_array() && !mesh["primitives"].empty()) {
            auto& prim = mesh["primitives"][rng() % mesh["primitives"].size()];
            if (prim.is_object()) {
                if (rng() % 2 == 0 && prim.contains("indices") && prim["indices"].is_number()) {
                    prim["indices"] = mutateBoundary(prim["indices"].get<uint64_t>(), rng);
                } else if (prim.contains("attributes") && prim["attributes"].is_object() && !prim["attributes"].empty()) {
                    for (auto& [attrName, attrVal] : prim["attributes"].items()) {
                        if (attrVal.is_number()) {
                            attrVal = mutateBoundary(attrVal.get<uint64_t>(), rng);
                            break;
                        }
                    }
                }
            }
        }
    }
    // Action 5: Mutate Node hierarchy & Scenes
    else if (action == 5 && j.contains("nodes") && j["nodes"].is_array() && !j["nodes"].empty()) {
        auto& node = j["nodes"][rng() % j["nodes"].size()];
        if (node.is_object()) {
            if (node.contains("mesh") && node["mesh"].is_number()) {
                node["mesh"] = mutateBoundary(node["mesh"].get<uint64_t>(), rng);
            }
            if (rng() % 2 == 0) {
                // Mutate children array (cycle insertion)
                node["children"] = {0, 1, 2};
            }
        }
    }
    // Action 6: Duplicate keys or raw array mutations
    else {
        if (j.contains("extensionsRequired")) {
            j["extensionsRequired"].push_back("KHR_draco_mesh_compression");
        } else {
            j["extensionsRequired"] = nlohmann::json::array({"KHR_unknown_extension_fuzz"});
        }
    }
}

// Strategy B: Raw textual mutations on JSON strings
std::string mutateJsonTextual(const std::string& input, std::mt19937& rng) {
    if (input.empty()) return "{}";
    std::string text = input;
    uint32_t action = rng() % 5;

    if (action == 0) {
        // Insert duplicate key
        size_t pos = text.find("\"asset\"");
        if (pos != std::string::npos) {
            text.insert(pos, "\"asset\": {\"version\": \"2.0\"}, ");
        }
    } else if (action == 1) {
        // Insert extreme number representation
        static const std::vector<std::string> NUMBERS = {
            "1e99999", "-1e99999", "1e-99999", "-0.0", "NaN", "Infinity", "0.00000000000000000000001"
        };
        size_t pos = text.find("5126");
        if (pos != std::string::npos) {
            text.replace(pos, 4, NUMBERS[rng() % NUMBERS.size()]);
        }
    } else if (action == 2) {
        // Truncate or alter quote / brace
        if (text.size() > 5) {
            size_t idx = rng() % text.size();
            text[idx] = (rng() % 2 == 0) ? '{' : '}';
        }
    } else if (action == 3) {
        // Truncate trailing characters
        size_t cut = (rng() % 8) + 1;
        if (text.size() > cut) {
            text.resize(text.size() - cut);
        }
    } else {
        // Insert percent sequence into a quoted string
        size_t pos = text.find("\"uri\"");
        if (pos != std::string::npos) {
            text.insert(pos + 7, "%25%00%A");
        }
    }
    return text;
}

// Mutate parsed GLB container
void mutateGlbContainer(GlbContainer& glb, std::mt19937& rng, bool repair) {
    uint32_t action = rng() % 5;
    if (action == 0) {
        // Mutate header fields
        uint32_t sub = rng() % 3;
        if (sub == 0) glb.magic = (rng() % 2 == 0) ? 0x12345678 : 0x00000000;
        else if (sub == 1) glb.version = (rng() % 4);
        else glb.declaredTotalLength = mutateBoundary(glb.declaredTotalLength, rng);
    } else if (action == 1 && !glb.chunks.empty()) {
        // Mutate JSON chunk
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
        // Mutate BIN chunk
        for (auto& chunk : glb.chunks) {
            if (chunk.chunkType == GLB_CHUNK_BIN && !chunk.data.empty()) {
                size_t sz = chunk.data.size();
                uint32_t sub = rng() % 3;
                if (sub == 0 && sz > 4) {
                    chunk.data.resize(sz / 2); // Truncate
                } else if (sub == 1) {
                    chunk.data.resize(sz + 16, 0xFF); // Extend
                } else {
                    chunk.chunkLength = mutateBoundary(chunk.chunkLength, rng);
                }
                break;
            }
        }
    } else if (action == 3) {
        // Mutate chunk ordering or chunk types
        if (glb.chunks.size() >= 2) {
            std::swap(glb.chunks[0], glb.chunks[1]);
        }
    } else {
        // Add random or invalid chunk
        GlbChunk newChunk;
        newChunk.chunkType = 0xDEADBEEF;
        newChunk.chunkLength = 16;
        newChunk.data.resize(16, 0x42);
        glb.chunks.push_back(std::move(newChunk));
    }
}

} // namespace

size_t mutatePayload(uint8_t* data, size_t size, size_t maxSize, unsigned int seed, FuzzMode mode) {
    if (size < 1 || maxSize < 2) {
        return size;
    }

    std::mt19937 rng(seed);

    // Envelope: byte 0 is profile byte, rest is payload
    uint8_t profile = data[0];
    // 90% chance preserve profile byte, 10% mutate profile
    if ((rng() % 10) == 0) {
        profile = static_cast<uint8_t>(rng() % static_cast<uint8_t>(ConfigProfile::NumProfiles));
    }

    uint8_t* payload = data + 1;
    size_t payloadSize = size - 1;
    size_t maxPayloadSize = maxSize - 1;

    // Byte-level mode
    if (mode == FuzzMode::Byte) {
        size_t newPayloadSize = LLVMFuzzerMutate(payload, payloadSize, maxPayloadSize);
        data[0] = profile;
        return 1 + newPayloadSize;
    }

    // Hybrid mode probability roll:
    // 25% byte mutation fallback
    // 25% valid-preserving struct mutation (repair = true)
    // 40% invariant-breaking struct mutation (repair = false)
    // 10% procedural generation
    uint32_t roll = rng() % 100;
    if (mode == FuzzMode::Hybrid && roll < 25) {
        size_t newPayloadSize = LLVMFuzzerMutate(payload, payloadSize, maxPayloadSize);
        data[0] = profile;
        return 1 + newPayloadSize;
    }

    if (mode == FuzzMode::Hybrid && roll >= 90) {
        // Procedural generation arm
        std::vector<uint8_t> genBytes;
        if (rng() % 2 == 0) {
            genBytes = GltfGenerator::generateGlb(seed);
        } else {
            std::string s = (rng() % 2 == 0) ? GltfGenerator::generateJsonGltf(seed)
                                            : GltfGenerator::generateSparseJsonGltf(seed);
            genBytes.assign(s.begin(), s.end());
        }
        if (genBytes.size() <= maxPayloadSize) {
            data[0] = profile;
            std::memcpy(data + 1, genBytes.data(), genBytes.size());
            return 1 + genBytes.size();
        }
    }

    bool repair = (mode == FuzzMode::Hybrid) ? (roll < 50) : false;

    // Check if payload is GLB
    if (GlbParser::isGlb(payload, payloadSize)) {
        GlbContainer container;
        if (GlbParser::parse(payload, payloadSize, container)) {
            mutateGlbContainer(container, rng, repair);
            auto serialized = GlbParser::serialize(container, repair);
            if (serialized.size() <= maxPayloadSize && !serialized.empty()) {
                data[0] = profile;
                std::memcpy(data + 1, serialized.data(), serialized.size());
                return 1 + serialized.size();
            }
        }
    }

    // Check if payload resembles JSON (first non-space character is '{')
    size_t firstNonWs = 0;
    while (firstNonWs < payloadSize && (payload[firstNonWs] == ' ' || payload[firstNonWs] == '\t' ||
                                        payload[firstNonWs] == '\r' || payload[firstNonWs] == '\n')) {
        ++firstNonWs;
    }

    if (firstNonWs < payloadSize && payload[firstNonWs] == '{') {
        std::string jsonStr(reinterpret_cast<const char*>(payload), payloadSize);
        try {
            auto j = nlohmann::json::parse(jsonStr);
            mutateJsonAst(j, rng, repair);
            std::string mutated = j.dump();
            if (mutated.size() <= maxPayloadSize) {
                data[0] = profile;
                std::memcpy(data + 1, mutated.data(), mutated.size());
                return 1 + mutated.size();
            }
        } catch (...) {
            // DOM parse failed, apply raw textual mutation
            std::string mutated = mutateJsonTextual(jsonStr, rng);
            if (mutated.size() <= maxPayloadSize) {
                data[0] = profile;
                std::memcpy(data + 1, mutated.data(), mutated.size());
                return 1 + mutated.size();
            }
        }
    }

    // Fallback to libFuzzer ordinary byte mutation
    size_t newPayloadSize = LLVMFuzzerMutate(payload, payloadSize, maxPayloadSize);
    data[0] = profile;
    return 1 + newPayloadSize;
}

} // namespace fastgltf_fuzz

extern "C" size_t LLVMFuzzerCustomMutator(uint8_t *Data, size_t Size, size_t MaxSize, unsigned int Seed) {
    fastgltf_fuzz::FuzzMode mode = fastgltf_fuzz::getFuzzMode();
    return fastgltf_fuzz::mutatePayload(Data, Size, MaxSize, Seed, mode);
}
