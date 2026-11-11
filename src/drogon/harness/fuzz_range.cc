/* HTTP Range header parser (drogon::parseRangeHeader), used when serving static files. A malformed
 * "Range:" value with an attacker-chosen content length drives the byte-range arithmetic (multi-
 * range, suffix ranges, overflow of start/end). Input: the range string is the front; the content
 * length is a u32 read from the tail (so a raw header line is a valid seed). Ranges are half-open
 * [start, end); oracle: every returned range satisfies start < end <= contentLength. */
extern "C" {
#include "fuzz_common.h"
}
#include "fuzz_mock.h"
#include "RangeParser.h"
#include <string>
#include <vector>

using namespace drogon;
FZ_USE_BINARY_MUTATOR

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *d, size_t n) {
    fz::init();
    if (n > (1u << 16)) return 0;

    fz_rd r = { n >= 4 ? d + n - 4 : d, n >= 4 ? 4 : n };
    size_t wire = n >= 4 ? n - 4 : n;
    size_t contentLength = fz_u32(&r);

    std::string range(reinterpret_cast<const char *>(d), wire);
    std::vector<FileRange> ranges;
    FileRangeParseResult res = parseRangeHeader(range, contentLength, ranges);

    if (res == SinglePart || res == MultiPart) {
        for (const auto &fr : ranges)
            FUZZ_ORACLE(fr.start < fr.end && fr.end <= contentLength,
                        "parseRangeHeader returned out-of-bounds range");
    }
    return 0;
}
