#include <iostream>
#include <string>
#include <cassert>
#include <trantor/utils/MsgBuffer.h>
#include "HttpRequestParser.h"

int main()
{
    std::cout << "[*] Investigating HTTP header boundary flaw in HttpRequestParser...\n";
    std::string malformedRequest = 
        "GET /test HTTP/1.1\r\n"
        "Host: example.com\r\n"
        "BadHeaderNoColon\r\n"
        "Injected-Header: admin\r\n\r\n";

    drogon::HttpRequestParser parser;
    trantor::MsgBuffer buf;
    buf.append(malformedRequest);

    auto result = parser.parseRequest(&buf);
    std::cout << "    Parse result: " << static_cast<int>(result) << "\n";

    if (result != drogon::HttpRequestParseResult::kBadMessage)
    {
        std::cout << "[!] VULNERABILITY CONFIRMED: Malformed header did NOT return kBadMessage (400 Bad Request)!\n";
        std::cout << "    Instead, parser treated 'BadHeaderNoColon' as end-of-headers, leaving subsequent headers to leak into body.\n";
    }
    else
    {
        std::cout << "[+] PASSED: Malformed header was strictly rejected with kBadMessage (400 Bad Request).\n";
    }

    return 0;
}

