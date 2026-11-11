/* HTTP/1.x request parser — the primary untrusted-input surface. Drives drogon::HttpRequestParser
 * exactly as HttpServer::onMessage() does: bytes arrive in attacker-chosen slices (a MsgBuffer fed
 * incrementally), so the parser's state machine (method / request-line / headers / body / chunked /
 * pipelining) is exercised across packet boundaries — the HTTP analogue of the raylib image_ops VM,
 * where bugs need a *sequence* of partial feeds, not one blob.
 *
 * After each fully-parsed request we poke the lazy post-parse parsers the framework runs per
 * request: query/parameter splitting, header & cookie maps, content-type, and (for json bodies)
 * jsoncpp. Oracle: realContentLength() must equal the bytes we actually sent as body.
 *
 * The slice schedule is read from the TAIL, so a raw .http file is a valid seed (front = real
 * request bytes). */
extern "C" {
#include "fuzz_common.h"
}
#include "fuzz_mock.h"
#include <trantor/utils/MsgBuffer.h>
#include "HttpRequestParser.h"
#include "HttpRequestImpl.h"
#include <memory>

using namespace drogon;
FZ_USE_BINARY_MUTATOR

static void poke(const HttpRequestImplPtr &req) {
    if (!req) return;
    (void)req->getParameters();     // parseParametersOnce: query string + x-www-form-urlencoded body
    (void)req->getHeaders();
    (void)req->getCookies();
    (void)req->getPath();
    (void)req->path();              // percent-decode path
    (void)req->getQuery();
    (void)req->contentType();
    (void)req->getBody();
    if (req->contentType() == CT_APPLICATION_JSON)
        (void)req->getJsonObject();  // jsoncpp parse of attacker body
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *d, size_t n) {
    fz::init();
    if (n > (2u << 20)) return 0;

    // Parameters from the tail; everything before is the wire bytes.
    fz_rd r = { n >= 4 ? d + n - 4 : d, n >= 4 ? 4 : n };
    size_t wire = n >= 4 ? n - 4 : n;

    auto parser = std::make_shared<HttpRequestParser>(fz::conn());
    parser->reset();
    trantor::MsgBuffer buf;

    size_t off = 0; int guard = 0;
    while (off < wire && guard++ < 4096) {
        // feed a slice (edge-biased small so header/body boundaries land mid-token)
        size_t step = (size_t)fz_int_edge(&r, 1, 64);
        if (step == 0) step = 1;
        if (step > wire - off) step = wire - off;
        buf.append(reinterpret_cast<const char *>(d + off), step);
        off += step;

        // drain like the server: parse repeatedly until it needs more bytes or errors
        for (;;) {
            if (parser->isStop()) { buf.retrieveAll(); break; }
            int res = parser->parseRequest(&buf);
            if (res < 0) { buf.retrieveAll(); parser->stop(); break; }
            if (res == 0) break;                      // need more data
            if (res == 1 || res == 2) {               // a request is ready (non-stream / stream)
                auto &req = parser->requestImpl();
                poke(req);
                // In non-stream mode the whole body is buffered in memory while it stays under
                // clientMaxMemoryBodySize (64 KB default); above that it spills to a cache file and
                // getBody() no longer mirrors it. Only assert the invariant in the in-memory regime.
                if (res == 1 && req->realContentLength() < 60000)
                    FUZZ_ORACLE(req->realContentLength() == req->getBody().size(),
                                "realContentLength != buffered body bytes");
                parser->reset();
            }
            // res == 3 (header-ready stream mode) only occurs when request stream is enabled (off).
        }
    }
    return 0;
}
