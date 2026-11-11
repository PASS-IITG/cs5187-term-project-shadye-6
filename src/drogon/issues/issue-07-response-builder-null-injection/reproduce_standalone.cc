#include <iostream>
#include <string>
#include <cassert>
#include <drogon/HttpResponse.h>
#include "HttpUtils.h"

int main()
{
    std::cout << "[*] Investigating Header Null Byte Rejection in isValidHeader...\n";

    std::string headerName = "X-Injected";
    std::string headerValueWithNull = std::string("test\0admin=1", 12);

    bool isValid = drogon::isValidHeader(headerName, headerValueWithNull);
    std::cout << "    Input: header with embedded null byte '\\0'\n";
    std::cout << "    isValidHeader() result: " << (isValid ? "VALID (VULNERABLE)" : "INVALID (REJECTED)") << "\n";

    if (isValid)
    {
        std::cout << "[!] VULNERABILITY: isValidHeader permitted embedded null byte in HTTP header!\n";
    }
    else
    {
        std::cout << "[+] PASSED: isValidHeader correctly rejected embedded null byte.\n";
    }

    return 0;
}

