/* drogon::utils codecs & hashes — the Drogon analogue of raylib's fuzz_codec. A mode byte selects
 * either a *hostile decode* of attacker bytes (base64 / url / gzip / brotli decompress — crash
 * finding) or a *differential round-trip* that is a true oracle:
 *     base64Decode(base64Encode(x))   == x
 *     urlDecode(urlEncode(x))         == x
 *     gzipDecompress(gzipCompress(x)) == x
 *     brotliDecompress(brotliCompress(x)) == x   (no-op when brotli wasn't built)
 * plus hash determinism. Oracles disable with FUZZ_NO_ORACLE=1. */
extern "C" {
#include "fuzz_common.h"
}
#include "fuzz_mock.h"
#include <drogon/utils/Utilities.h>
#include <string>

using namespace drogon;
FZ_USE_BINARY_MUTATOR

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *d, size_t n) {
    fz::init();
    if (n == 0 || n > (1u << 20)) return 0;
    uint8_t mode = d[0]; d++; n--;
    std::string in(reinterpret_cast<const char *>(d), n);
    std::string_view sv(in);

    switch (mode % 8) {
    case 0: (void)utils::base64Decode(sv); break;                 // hostile
    case 1: (void)utils::urlDecode(in); break;                    // hostile
    case 2: (void)utils::gzipDecompress(in.data(), in.size()); break;   // hostile
#ifdef USE_BROTLI
    case 3: (void)utils::brotliDecompress(in.data(), in.size()); break; // hostile
#else
    case 3: break; // brotli not built
#endif
    case 4: {
        std::string enc = utils::base64Encode(sv);
        std::string dec = utils::base64Decode(enc);
        FUZZ_ORACLE(dec == in, "base64 round-trip mismatch");
        break;
    }
    case 5: {
        std::string enc = utils::urlEncode(in);
        std::string dec = utils::urlDecode(enc);
        FUZZ_ORACLE(dec == in, "urlEncode/urlDecode round-trip mismatch");
        break;
    }
    case 6: {
        std::string c = utils::gzipCompress(in.data(), in.size());
        if (!c.empty()) {
            std::string back = utils::gzipDecompress(c.data(), c.size());
            FUZZ_ORACLE(back == in, "gzip round-trip mismatch");
        }
        break;
    }
    case 7: {
        std::string c = utils::brotliCompress(in.data(), in.size());
        if (!c.empty()) {                                          // empty => brotli not built
            std::string back = utils::brotliDecompress(c.data(), c.size());
            FUZZ_ORACLE(back == in, "brotli round-trip mismatch");
        }
        break;
    }
    }

    // Side checks on the raw bytes (classification + hash determinism).
    (void)utils::isValidUTF8(sv);
    (void)utils::isBase64(sv);
    (void)utils::utf8Length(sv);
    FUZZ_ORACLE(utils::getMd5(in) == utils::getMd5(in), "MD5 nondeterministic");
    (void)utils::getSha1(in); (void)utils::getSha256(in);
    return 0;
}
