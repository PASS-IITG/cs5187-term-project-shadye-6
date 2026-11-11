#include <fastgltf/types.hpp>
#include <cassert>
#include <iostream>

int main() {
    std::cout << "[Test] Running URI tests..." << std::endl;

    // Test 1: Standard URI parsing
    std::string testUri = "model.bin";
    fastgltf::URIView view(testUri);
    assert(view.valid());
    assert(view.isLocalPath());
    std::cout << "  Passed: Standard local URI" << std::endl;

    // Test 2: Data URI detection
    std::string dataUri = "data:application/octet-stream;base64,AAAA";
    fastgltf::URIView dataView(dataUri);
    assert(dataView.valid());
    assert(dataView.isDataUri());
    std::cout << "  Passed: Data URI detection" << std::endl;

    // Test 3: Truncated percent sequence safety
    std::string trunc1 = "test%";
    try {
        fastgltf::URI u1(trunc1);
        (void)u1;
    } catch (...) {
        // Exception caught safely
    }
    std::cout << "  Passed: Truncated % handled" << std::endl;

    std::cout << "[Test] All URI tests passed!" << std::endl;
    return 0;
}
