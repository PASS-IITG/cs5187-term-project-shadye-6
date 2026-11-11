#include <fastgltf/types.hpp>
#include <fastgltf/core.hpp>
#include <string_view>
#include <string>
#include <cstdint>
#include <cstddef>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size == 0) {
        return 0;
    }

    std::string_view rawUriView(reinterpret_cast<const char*>(Data), Size);

    // 1. Exercise URIView non-owning view parsing
    try {
        fastgltf::URIView view(rawUriView);
        volatile bool valid = view.valid();
        volatile bool local = view.isLocalPath();
        volatile bool dataUri = view.isDataUri();

        (void)view.scheme();
        (void)view.userinfo();
        (void)view.host();
        (void)view.port();
        (void)view.path();
        (void)view.query();
        (void)view.fragment();
        (void)valid;
        (void)local;
        (void)dataUri;

        if (view.valid() && view.isLocalPath()) {
            try {
                auto path = view.fspath();
                (void)path;
            } catch (const std::exception&) {
                // Catch standard filesystem path formatting exceptions
            }
        }
    } catch (const std::exception&) {
        // Safe exception capture
    }

    // 2. Exercise owning URI class with percent-decoding
    try {
        fastgltf::URI uri(rawUriView);
        volatile bool valid = uri.valid();
        volatile bool local = uri.isLocalPath();
        volatile bool dataUri = uri.isDataUri();

        (void)uri.string();
        (void)uri.c_str();
        (void)uri.scheme();
        (void)uri.userinfo();
        (void)uri.host();
        (void)uri.port();
        (void)uri.path();
        (void)uri.query();
        (void)uri.fragment();
        (void)valid;
        (void)local;
        (void)dataUri;

        if (uri.valid() && uri.isLocalPath()) {
            try {
                auto path = uri.fspath();
                (void)path;
            } catch (const std::exception&) {
            }
        }
    } catch (const std::exception&) {
    }

    // 3. Exercise direct percent decoding static helper
    try {
        std::string decodeStr(reinterpret_cast<const char*>(Data), Size);
        fastgltf::URI::decodePercents(decodeStr);
    } catch (const std::exception&) {
    }

    return 0;
}
