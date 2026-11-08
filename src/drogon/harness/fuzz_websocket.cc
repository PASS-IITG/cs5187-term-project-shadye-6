/* WebSocket frame parser (drogon::WebSocketMessageParser::parse) — the untrusted surface after a
 * WS upgrade: opcode/FIN/RSV bits, 7/16/64-bit payload lengths, client mask, fragmentation and
 * control-frame rules (RFC 6455). Frames are fed in fuzzed slices so the length/mask/continuation
 * state machine is crossed mid-frame. isServer is fuzzed (server expects masked frames; client
 * expects unmasked). On a completed message we drain it via gotAll(). No connection needed — the
 * message parser is self-contained. */
extern "C" {
#include "fuzz_common.h"
}
#include "fuzz_mock.h"
#include <trantor/utils/MsgBuffer.h>
#include "WebSocketConnectionImpl.h"
#include <string>

using namespace drogon;
FZ_USE_BINARY_MUTATOR

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *d, size_t n) {
    fz::init();
    if (n > (1u << 20)) return 0;

    fz_rd r = { n >= 3 ? d + n - 3 : d, n >= 3 ? 3 : n };
    size_t wire = n >= 3 ? n - 3 : n;
    bool isServer = (fz_u8(&r) & 1);

    WebSocketMessageParser parser;
    trantor::MsgBuffer buf;

    size_t off = 0; int guard = 0;
    while (off < wire && guard++ < 8192) {
        size_t step = (size_t)fz_int_edge(&r, 1, 48);
        if (step == 0) step = 1;
        if (step > wire - off) step = wire - off;
        buf.append(reinterpret_cast<const char *>(d + off), step);
        off += step;

        for (;;) {
            if (!parser.parse(&buf, isServer)) { buf.retrieveAll(); break; }  // protocol error
            std::string msg; WebSocketMessageType type;
            if (parser.gotAll(msg, type)) { (void)type; (void)msg.size(); continue; }
            break;   // need more bytes for the next frame
        }
    }
    return 0;
}
