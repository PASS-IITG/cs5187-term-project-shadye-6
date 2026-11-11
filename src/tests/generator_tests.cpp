#include "../generator/gltf_generator.hpp"
#include <fastgltf/core.hpp>
#include <cassert>
#include <iostream>

int main() {
    std::cout << "[Test] Running generator unit tests..." << std::endl;

    // Test 1: JSON glTF generator produces parseable glTF
    std::string json = fastgltf_fuzz::GltfGenerator::generateJsonGltf(1);
    assert(!json.empty());

    auto bufExp = fastgltf::GltfDataBuffer::FromBytes(
        reinterpret_cast<const std::byte*>(json.data()), json.size());
    assert(bufExp.error() == fastgltf::Error::None);

    fastgltf::Parser parser(fastgltf::Extensions::None);
    auto assetExp = parser.loadGltf(bufExp.get(), {}, fastgltf::Options::None);
    assert(assetExp.error() == fastgltf::Error::None);
    assert(!assetExp->meshes.empty());
    std::cout << "  Passed: Procedural JSON glTF is valid and loadable" << std::endl;

    // Test 2: GLB generator produces parseable GLB
    auto glbBytes = fastgltf_fuzz::GltfGenerator::generateGlb(2);
    assert(glbBytes.size() > 12);

    auto glbBufExp = fastgltf::GltfDataBuffer::FromBytes(
        reinterpret_cast<const std::byte*>(glbBytes.data()), glbBytes.size());
    assert(glbBufExp.error() == fastgltf::Error::None);

    fastgltf::Parser glbParser(fastgltf::Extensions::None);
    auto glbAssetExp = glbParser.loadGltf(glbBufExp.get(), {}, fastgltf::Options::None);
    if (glbAssetExp.error() != fastgltf::Error::None) {
        std::cerr << "GLB load failed with error: " << fastgltf::getErrorName(glbAssetExp.error())
                  << " (" << fastgltf::getErrorMessage(glbAssetExp.error()) << ")" << std::endl;
    }
    assert(glbAssetExp.error() == fastgltf::Error::None);
    std::cout << "  Passed: Procedural GLB is valid and loadable" << std::endl;

    // Test 3: Sparse JSON generator produces parseable glTF
    std::string sparseJson = fastgltf_fuzz::GltfGenerator::generateSparseJsonGltf(3);
    auto sparseBufExp = fastgltf::GltfDataBuffer::FromBytes(
        reinterpret_cast<const std::byte*>(sparseJson.data()), sparseJson.size());
    assert(sparseBufExp.error() == fastgltf::Error::None);
    auto sparseAssetExp = parser.loadGltf(sparseBufExp.get(), {}, fastgltf::Options::None);
    assert(sparseAssetExp.error() == fastgltf::Error::None);
    std::cout << "  Passed: Procedural Sparse glTF is valid and loadable" << std::endl;

    std::cout << "[Test] All generator tests passed!" << std::endl;
    return 0;
}
