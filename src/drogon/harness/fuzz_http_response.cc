/* HTTP/1.x response parser (client side): drogon::HttpResponseParser, driven incrementally like
 * HttpClientImpl. Covers status line, headers, content-length & chunked bodies, HEAD-method framing,
 * and the connection-close body path (parseResponseOnClose). A fuzzed "head method" flag flips the
 * no-body interpretation. Post-parse pokes exercise the lazy jsoncpp/cookie parsing of the body. */
extern "C" {
#include "fuzz_common.h"
}
#include "fuzz_mock.h"
#include <trantor/utils/MsgBuffer.h>
#include "HttpResponseParser.h"
#include "HttpResponseImpl.h"
#include <memory>

using namespace drogon;
FZ_USE_BINARY_MUTATOR

static void poke(const HttpResponseImplPtr &resp) {
    if (!resp) return;
    (void)resp->getHeaders();
    (void)resp->getCookies();
    (void)resp->statusCode();
    (void)resp->getBody();
    (void)resp->contentType();
    (void)resp->getJsonObject();
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *d, size_t n) {
    fz::init();
    if (n > (2u << 20)) return 0;

    fz_rd r = { n >= 5 ? d + n - 5 : d, n >= 5 ? 5 : n };
    size_t wire = n >= 5 ? n - 5 : n;
    bool headMethod = (fz_u8(&r) & 1);
    bool closeAtEnd = (fz_u8(&r) & 1);

    auto parser = std::make_shared<HttpResponseParser>(fz::conn());
    parser->reset();
    if (headMethod) parser->setForHeadMethod();
    trantor::MsgBuffer buf;

    size_t off = 0; int guard = 0;
    while (off < wire && guard++ < 4096) {
        size_t step = (size_t)fz_int_edge(&r, 1, 64);
        if (step == 0) step = 1;
        if (step > wire - off) step = wire - off;
        buf.append(reinterpret_cast<const char *>(d + off), step);
        off += step;

        for (;;) {
            if (!parser->parseResponse(&buf)) { buf.retrieveAll(); break; }  // parse error
            if (parser->gotAll()) {
                poke(parser->responseImpl());
                parser->reset();
                if (headMethod) parser->setForHeadMethod();
                if (buf.readableBytes() == 0) break;
                continue;                   // pipelined next response
            }
            break;                          // need more data
        }
    }
    // Connection-close terminates a body with no content-length (HTTP/1.0 style).
    if (closeAtEnd && parser->parseResponseOnClose() && parser->gotAll())
        poke(parser->responseImpl());
    return 0;
}
