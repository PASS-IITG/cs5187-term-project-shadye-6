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

void runStrictPrefixTest(const fs::path &uploadDir)
{
    drogon::HttpFileImpl file;
    // Strict prefix: For upload directory tempBase/a/b/c/upload,
    // filename "../../c" resolves to weakly_canonical path tempBase/a/b/c without trailing slash.
    // This produces a strict prefix with fewer path components than the upload root.
    file.setFileName("../../c");
    const char dummy[] = "TEST_DATA_PAYLOAD";
    file.setFile(dummy, sizeof(dummy));

    // This invokes the 3-iterator std::equal in HttpFileImpl.cc:75
    // Because fsSaveToPath is a strict prefix with fewer components,
    // std::equal dereferences past fsSaveToPath.end().
    file.save();
}

int main()
{
    std::cout << "[*] Investigating candidate Undefined Behavior in HttpFileImpl::save()...\n";
    std::cout << "    Target: 3-iterator std::equal(fsUploadDir.begin(), fsUploadDir.end(), fsSaveToPath.begin())\n";

    fs::path tempBase = fs::temp_directory_path() / ("drogon_ub_test_" + std::to_string(::getpid()));
    fs::path uploadDir = tempBase / "a" / "b" / "c" / "upload";
    std::error_code ec;
    fs::create_directories(uploadDir, ec);

    drogon::app().setUploadPath(uploadDir.string());

    fs::path targetShorter = fs::weakly_canonical(uploadDir / "../../c");
    size_t uploadCount = std::distance(uploadDir.begin(), uploadDir.end());
    size_t shorterCount = std::distance(targetShorter.begin(), targetShorter.end());

    std::cout << "    fsUploadDir:  " << uploadDir << " (" << uploadCount << " components)\n";
    std::cout << "    fsSaveToPath: " << targetShorter << " (" << shorterCount << " components)\n";
    std::cout << "    [!] Condition verified: Destination path has FEWER components than upload root!\n";
    assert(shorterCount < uploadCount);

    // Create pipe to capture child stderr
    int pipeFds[2];
    if (::pipe(pipeFds) < 0)
    {
        std::cerr << "[-] Error: pipe() failed!\n";
        fs::remove_all(tempBase, ec);
        return 1;
    }

    // Isolate strict-prefix out-of-bounds dereference in a child process
    pid_t pid = fork();
    if (pid < 0)
    {
        std::cerr << "[-] Error: fork() failed!\n";
        ::close(pipeFds[0]);
        ::close(pipeFds[1]);
        fs::remove_all(tempBase, ec);
        return 1;
    }

    if (pid == 0)
    {
        // Child process: redirect stderr to pipe and execute the out-of-bounds dereference
        ::close(pipeFds[0]);
        ::dup2(pipeFds[1], STDERR_FILENO);
        ::close(pipeFds[1]);

        runStrictPrefixTest(uploadDir);
        _exit(0);
    }

    ::close(pipeFds[1]);

    // Read child stderr
    std::string childStderr;
    char readBuf[1024];
    ssize_t bytesRead = 0;
    while ((bytesRead = ::read(pipeFds[0], readBuf, sizeof(readBuf) - 1)) > 0)
    {
        readBuf[bytesRead] = '\0';
        childStderr.append(readBuf, bytesRead);
    }
    ::close(pipeFds[0]);

    int status = 0;
    if (waitpid(pid, &status, 0) < 0)
    {
        std::cerr << "[-] Error: waitpid() failed!\n";
        fs::remove_all(tempBase, ec);
        return 1;
    }

    std::cout << "    Captured child stderr:\n" << childStderr << "\n";

    bool defectVerified = false;
    if (WIFSIGNALED(status) && (WTERMSIG(status) == SIGABRT || WTERMSIG(status) == SIGSEGV))
    {
        // Require explicit libstdc++ past-end / iterator precondition assertion diagnostic (F-08)
        if (childStderr.find("past-end") != std::string::npos ||
            childStderr.find("iterator") != std::string::npos ||
            childStderr.find("assert") != std::string::npos)
        {
            std::cout << "    [CONFIRMED DEFECT] Child process aborted with signal "
                      << WTERMSIG(status) << " and libstdc++ past-end iterator assertion confirmed!\n";
            defectVerified = true;
        }
        else
        {
            std::cerr << "    [-] Child process aborted but lacked expected libstdc++ iterator assertion diagnostic.\n";
        }
    }
    else
    {
        std::cerr << "    [-] Child process did not abort as expected (exit status: " << status << ")\n";
    }

    fs::remove_all(tempBase, ec);
    return defectVerified ? 0 : 1;
}
