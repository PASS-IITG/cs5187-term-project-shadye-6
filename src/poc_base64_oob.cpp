#include <fastgltf/base64.hpp>
#include <iostream>
#include <string>

int main(int argc, char** argv) {
    std::string mode = (argc > 1) ? argv[1] : "bad";
    if (mode == "control") {
        std::string ascii = "AAAA";
        std::cout << "[*] Control Test: Decoding valid ASCII 'AAAA'..." << std::endl;
        auto res = fastgltf::base64::fallback_decode(ascii);
        std::cout << "[*] Control Test PASSED. Decoded bytes: " << res.size() << std::endl;
        return 0;
    }

    std::string bad = "AA\xfe=";
    std::cout << "[*] Bad Test: Decoding high-byte 'AA\\xfe='..." << std::endl;
    auto res = fastgltf::base64::fallback_decode(bad);
    std::cout << "[*] Bad Test finished without bounds abort. Decoded bytes: " << res.size() << std::endl;
    return 0;
}
