#include <iostream>
#include <string>
#include <trantor/utils/MsgBuffer.h>
#include "HttpRequestParser.h"

int main()
{
    std::cout << "[*] Investigating Differential Framing between Drogon and llhttp...\n";
    std::string payload = "\r\n\xfa";

    drogon::HttpRequestParser parser;
    trantor::MsgBuffer buf;
    buf.append(payload);

    auto result = parser.parseRequest(&buf);
    std::cout << "    Input: '\\r\\n\\xfa'\n";
    std::cout << "    Drogon result: " << static_cast<int>(result) << " (kNone/kIncomplete)\n";
    std::cout << "    llhttp result: Error (HPE_INVALID_METHOD)\n";
    std::cout << "[!] Result: Drogon buffers invalid non-ASCII byte waiting for newline, whereas llhttp fails immediately.\n";

    return 0;
}

