#include <iostream>
#include <string>
#include <cassert>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <trantor/utils/MsgBuffer.h>
#include "HttpResponseParser.h"

void runStatusLineParse(const std::string &rawResponse)
{
    drogon::HttpResponseParser parser;
    trantor::MsgBuffer buffer;
    buffer.append(rawResponse);
    parser.parseResponse(&buffer);
}

int main()
{
    std::cout << "[*] Investigating Undefined Behavior in HttpResponseParser status code parsing...\n";
    std::cout << "    Target: drogon::HttpResponseParser::processResponseLine() -> setStatusCode(HttpStatusCode(code))\n";

    // Non-standard / out-of-range status code (e.g. 20020 or 220220 or 707)
    std::string malformedResponse = "HTTP/1.1 20020 OK\r\nContent-Length: 0\r\n\r\n";

    int pipeFds[2];
    if (::pipe(pipeFds) < 0)
    {
        std::cerr << "[-] Error: pipe() failed!\n";
        return 1;
    }

    pid_t pid = ::fork();
    if (pid < 0)
    {
        std::cerr << "[-] Fork failed!\n";
        return 1;
    }

    if (pid == 0)
    {
        ::close(pipeFds[0]);
        ::dup2(pipeFds[1], STDERR_FILENO);
        ::close(pipeFds[1]);

        runStatusLineParse(malformedResponse);
        _exit(0);
    }

    ::close(pipeFds[1]);
    char errBuffer[4096] = {0};
    ssize_t bytesRead = ::read(pipeFds[0], errBuffer, sizeof(errBuffer) - 1);
    ::close(pipeFds[0]);

    int status = 0;
    ::waitpid(pid, &status, 0);

    std::cout << "\n--- Child Process Diagnostic ---\n";
    if (bytesRead > 0)
    {
        std::cout << errBuffer << "\n";
    }

    if (WIFSIGNALED(status))
    {
        int sig = WTERMSIG(status);
        std::cout << "[!] RESULT: Child terminated with signal " << sig << " (" << strsignal(sig) << ")\n";
        if (sig == SIGABRT)
        {
            std::cout << "[+] CONFIRMED: UBSan aborted on invalid enum value load (load-invalid-value)!\n";
            return 0;
        }
    }
    else if (WIFEXITED(status))
    {
        int exitCode = WEXITSTATUS(status);
        std::cout << "[*] Child exited with code: " << exitCode << "\n";
    }

    return 0;
}

