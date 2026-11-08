#include <iostream>
#include <string>
#include <fstream>
#include <vector>
#include <cassert>
#include <drogon/HttpRequest.h>
#include <drogon/MultiPart.h>
#include "MultipartStreamParser.h"

int main(int argc, char **argv)
{
    std::cout << "[*] Investigating Differential Desynchronization between MultiPartParser and MultipartStreamParser...\n";
    std::string crashFile = "crash-475fce340a06d371706e91e7cec3ec643c753461";
    if (argc > 1) crashFile = argv[1];

    std::ifstream in(crashFile, std::ios::binary);
    if (!in.is_open())
    {
        std::cerr << "[-] Error opening crash file: " << crashFile << "\n";
        return 1;
    }

    std::string payload((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    std::cout << "    Loaded trigger payload size: " << payload.size() << " bytes\n";

    std::string boundary = "----WebKitFormBoundary7MA4YWxkTrZu0gW";

    // 1. Buffered parser
    auto req = drogon::HttpRequest::newHttpRequest();
    req->setContentTypeCode(drogon::CT_MULTIPART_FORM_DATA);
    req->setBody(payload);

    drogon::MultiPartParser bufParser;
    int bufRes = bufParser.parse(req);
    auto &bufFiles = bufParser.getFiles();
    auto &bufParams = bufParser.getParameters();

    std::cout << "    [1] Buffered Parser Result: code=" << bufRes 
              << ", files=" << bufFiles.size() 
              << ", parameters=" << bufParams.size() << "\n";
    for (const auto &[k, v] : bufParams)
    {
        std::cout << "        param: '" << k << "' = '" << v << "'\n";
    }

    // 2. Streaming parser
    size_t streamedParts = 0;
    std::vector<std::string> streamedParamNames;
    drogon::MultipartStreamParser streamParser(boundary,
        [&](const drogon::MultipartStreamParser::Part &part) {
            streamedParts++;
            streamedParamNames.push_back(part.name);
        });
    streamParser.parse(payload.data(), payload.size());

    std::cout << "    [2] Streaming Parser Result: parts=" << streamedParts << "\n";
    for (const auto &name : streamedParamNames)
    {
        std::cout << "        streamed part: '" << name << "'\n";
    }

    if (bufParams.size() != streamedParts)
    {
        std::cout << "\n[!] CONFIRMED DIFFERENTIAL DISCREPANCY:\n";
        std::cout << "    Buffered parser extracted " << bufParams.size() << " parameters, but streaming parser found " << streamedParts << "!\n";
        std::cout << "    This discrepancy allows RFC 2046 boundary injection / parameter smuggling across frontend proxies.\n";
    }

    return 0;
}

