/* Whole-body multipart parser (drogon::MultiPartParser::parse) plus the HttpFile layer it builds.
 * Unlike the streaming parser this is the buffered path used by request handlers: it scans the full
 * body, splits parts, fills HttpFile objects and form parameters. We build a real HttpRequest
 * (POST + multipart content-type + body) and parse it, then walk the resulting files/params and
 * touch HttpFile accessors (name, type, md5, content) — no save() so nothing hits disk.
 * Input layout: [u8 ctLen][content-type][body]. */
extern "C" {
#include "fuzz_common.h"
}
#include "fuzz_mock.h"
#include <drogon/HttpRequest.h>
#include <drogon/MultiPart.h>
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
    if (ct.find("boundary") == std::string::npos)
        ct = "multipart/form-data; boundary=" + (got ? ct : std::string("abc"));
    std::string body(reinterpret_cast<const char *>(r.p), r.n);

    auto req = HttpRequest::newHttpRequest();
    req->setMethod(Post);
    req->addHeader("content-type", ct);
    req->setBody(std::move(body));

    MultiPartParser mp;
    if (mp.parse(req) != 0) return 0;
    for (const auto &f : mp.getFiles()) {
        (void)f.getFileName(); (void)f.getItemName(); (void)f.getFileType();
        (void)f.getContentType(); (void)f.fileLength();
        (void)f.fileContent();
        (void)f.getMd5();                 // hashes the uploaded bytes
    }
    for (const auto &kv : mp.getParameters()) { (void)kv.first; (void)kv.second; }
    return 0;
}
