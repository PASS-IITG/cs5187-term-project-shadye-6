#include <drogon/HttpAppFramework.h>
#include "HttpFileImpl.h"
#include <iostream>
#include <filesystem>
#include <cassert>
#include <unistd.h>

namespace fs = std::filesystem;

int main()
{
    fs::path tempBase = fs::temp_directory_path() / ("drogon_fix_test_" + std::to_string(::getpid()));
    fs::path uploadDir = tempBase / "uploads";
    std::error_code ec;
    fs::create_directories(uploadDir, ec);
    drogon::app().setUploadPath(uploadDir.string());

    std::cout << "[*] Upload directory: " << uploadDir << "\n";

    // Test 1: Normal valid file save
    {
        drogon::HttpFileImpl file;
        file.setFileName("normal_document.pdf");
        const char payload[] = "VALID_DOCUMENT_CONTENT";
        file.setFile(payload, sizeof(payload));

        int res = file.save();
        std::cout << "Test 1 (Normal file save): result = " << res << "\n";
        assert(res == 0 && "Normal file save failed!");
        assert(fs::exists(uploadDir / "normal_document.pdf") && "File was not written!");
        std::cout << "  [PASS] Normal file written successfully.\n";
    }

    // Test 2: Legitimate nested subpath file save (e.g. uploads/2026/11/doc.pdf)
    {
        fs::create_directories(uploadDir / "2026" / "11", ec);
        drogon::HttpFileImpl file;
        file.setFileName("2026/11/doc.pdf");
        const char payload[] = "NESTED_DOCUMENT_CONTENT";
        file.setFile(payload, sizeof(payload));

        int res = file.save();
        std::cout << "Test 2 (Nested subpath save): result = " << res << "\n";
        assert(res == 0 && "Nested subpath save failed!");
        assert(fs::exists(uploadDir / "2026" / "11" / "doc.pdf") && "Nested file was not written!");
        std::cout << "  [PASS] Nested subpath file written successfully.\n";
    }

    // Test 3: Traversal input '..'
    {
        drogon::HttpFileImpl file;
        file.setFileName("..");
        const char payload[] = "TRAVERSAL";
        file.setFile(payload, sizeof(payload));

        int res = file.save();
        std::cout << "Test 3 (Traversal '..'): result = " << res << " (expected -1)\n";
        assert(res == -1 && "Traversal was not rejected!");
        std::cout << "  [PASS] '..' correctly rejected without crash.\n";
    }

    // Test 4: Traversal input '../../c'
    {
        drogon::HttpFileImpl file;
        file.setFileName("../../c");
        const char payload[] = "TRAVERSAL";
        file.setFile(payload, sizeof(payload));

        int res = file.save();
        std::cout << "Test 4 (Traversal '../../c'): result = " << res << " (expected -1)\n";
        assert(res == -1 && "Traversal was not rejected!");
        std::cout << "  [PASS] '../../c' correctly rejected without crash.\n";
    }

    // Test 5: Absolute path traversal '/etc/passwd'
    {
        drogon::HttpFileImpl file;
        file.setFileName("/etc/passwd");
        const char payload[] = "TRAVERSAL";
        file.setFile(payload, sizeof(payload));

        int res = file.save();
        std::cout << "Test 5 (Absolute path '/etc/passwd'): result = " << res << " (expected -1)\n";
        assert(res == -1 && "Absolute path traversal was not rejected!");
        std::cout << "  [PASS] '/etc/passwd' correctly rejected without crash.\n";
    }

    fs::remove_all(tempBase, ec);
    std::cout << "\n[+] ALL 5 VERIFICATION CHECKS PASSED PERFECTLY!\n";
    return 0;
}
