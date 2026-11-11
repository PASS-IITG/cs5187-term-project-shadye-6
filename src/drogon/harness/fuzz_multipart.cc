/* Streaming multipart/form-data parser (drogon::MultipartStreamParser), the body parser used for
 * chunked uploads. Input layout: [u8 ctLen][content-type bytes][body...]; the content-type carries
 * the boundary (e.g. "multipart/form-data; boundary=X"), the body is fed to parse() in fuzzed
 * slices so the boundary state machine (first boundary / headers / body / epilogue) is crossed at
 * arbitrary offsets — the analogue of the raylib stateful VMs. Header/data callbacks consume output.
 * Seeds + the multipart dictionary keep the boundary token consistent between CT and body. */
extern "C" {
#include "fuzz_common.h"
}
#include "fuzz_mock.h"
#include "MultipartStreamParser.h"
#include <drogon/RequestStream.h>
#include <string>

using namespace drogon;
FZ_USE_BINARY_MUTATOR

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *d, size_t n) {
    fz::init();
    if (n == 0 || n > (1u << 20)) return 0;

    fz_rd r = { d, n };
    size_t ctLen = fz_u8(&r);
    size_t got; const uint8_t *ctp = fz_bytes(&r, ctLen, &got);
    std::string ct(reinterpret_cast<const char *>(ctp), got);
    // Default to a well-formed multipart content-type when the seed didn't supply one, so the
    // parser gets past construction and the body bytes drive coverage.
    if (ct.find("boundary") == std::string::npos)
        ct = "multipart/form-data; boundary=" + (got ? ct : std::string("abc"));

    MultipartStreamParser parser(ct);
    if (!parser.isValid()) return 0;

    auto headerCb = [](MultipartHeader h) { (void)h.name; (void)h.filename; (void)h.contentType; };
    auto dataCb   = [](const char *p, size_t len) { (void)p; (void)len; };

    // Body = remaining bytes minus a small tail used as the slice schedule (so schedule bytes don't
    // double as body content).
    const uint8_t *body = r.p; size_t blen = r.n;
    size_t sched = blen >= 4 ? 4 : 0; blen -= sched;
    fz_rd sr = { body + blen, sched };

    size_t off = 0; int guard = 0;
    while (off < blen && parser.isValid() && !parser.isFinished() && guard++ < 8192) {
        size_t step = (size_t)fz_int_edge(&sr, 1, 128);
        if (step == 0) step = 1;
        if (step > blen - off) step = blen - off;
        parser.parse(reinterpret_cast<const char *>(body + off), step, headerCb, dataCb);
        off += step;
    }
    return 0;
}
