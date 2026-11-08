#include <iostream>
#include <fstream>
#include <filesystem>
#include <vector>
#include <cstdint>
#include <csignal>
#include <csetjmp>

namespace fs = std::filesystem;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);

static sigjmp_buf g_jump_buf;
static volatile sig_atomic_t g_in_target = 0;

static void crash_handler(int sig) {
    if (g_in_target) {
        g_in_target = 0;
        siglongjmp(g_jump_buf, 1);
    }
    _exit(1);
}

void processFile(const fs::path& filePath) {
    std::ifstream file(filePath, std::ios::binary | std::ios::ate);
    if (!file.is_open()) return;
    auto size = file.tellg();
    if (size <= 0) return;
    file.seekg(0, std::ios::beg);
    std::vector<uint8_t> buffer(size);
    if (!file.read(reinterpret_cast<char*>(buffer.data()), size)) return;

    if (sigsetjmp(g_jump_buf, 1) == 0) {
        g_in_target = 1;
        LLVMFuzzerTestOneInput(buffer.data(), buffer.size());
        g_in_target = 0;
    } else {
        // Recovered from crash/assert, continuing coverage collection
        g_in_target = 0;
    }
}

int main(int argc, char** argv) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <corpus_path_or_file...>" << std::endl;
        return 1;
    }

    signal(SIGABRT, crash_handler);
    signal(SIGSEGV, crash_handler);
    signal(SIGBUS, crash_handler);
    signal(SIGFPE, crash_handler);
    signal(SIGILL, crash_handler);

    for (int i = 1; i < argc; ++i) {
        fs::path p(argv[i]);
        if (!fs::exists(p)) continue;
        if (fs::is_directory(p)) {
            for (const auto& entry : fs::recursive_directory_iterator(p)) {
                if (entry.is_regular_file()) {
                    processFile(entry.path());
                }
            }
        } else if (fs::is_regular_file(p)) {
            processFile(p);
        }
    }
    return 0;
}
