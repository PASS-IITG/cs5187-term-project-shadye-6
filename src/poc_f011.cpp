#include <fastgltf/core.hpp>
#include <iostream>
#include <fstream>
#include <vector>

int main(int argc, char** argv) {
    const char* path = (argc > 1) ? argv[1] : "findings/crashes/crash-db0170fae561bcc1186860580e462803e93ecac1";
    std::ifstream file(path, std::ios::binary);
    if (!file) {
        std::cerr << "Could not open " << path << std::endl;
        return 1;
    }
    std::vector<char> chars((std::istreambuf_iterator<char>(file)),
                             std::istreambuf_iterator<char>());

    const uint8_t* dataPtr = reinterpret_cast<const uint8_t*>(chars.data());
    size_t dataSize = chars.size();
    if (dataSize > 1 && dataPtr[0] <= 7) {
        dataPtr += 1;
        dataSize -= 1;
    }

    auto buffer = fastgltf::GltfDataBuffer::FromBytes(
        reinterpret_cast<const std::byte*>(dataPtr), dataSize);
    if (buffer.error() != fastgltf::Error::None) {
        std::cerr << "Buffer error\n";
        return 1;
    }

    fastgltf::Parser parser;
    std::cout << "[*] Calling loadGltf with Options::GenerateMeshIndices..." << std::endl;
    auto assetExpected = parser.loadGltf(buffer.get(), {}, fastgltf::Options::GenerateMeshIndices);
    if (assetExpected.error() != fastgltf::Error::None) {
        std::cout << "[*] Parse error: " << fastgltf::to_underlying(assetExpected.error()) << "\n";
    } else {
        std::cout << "[*] Completed loadGltf successfully." << std::endl;
    }
    return 0;
}
