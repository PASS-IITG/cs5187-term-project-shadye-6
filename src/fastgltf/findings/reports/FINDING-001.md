# Vulnerability Report: FINDING-001

- **Summary**: SEGV in fastgltf::base64::getPadding
- **Affected fastgltf version**: v0.9.1
- **Commit**: 705564d4d54500ae88befb0db9e361e447923655
- **Environment**: Linux under WSL2 Ubuntu 24.04, Clang 18.1.3
- **Input Size**: 801 bytes
- **Finding Class**: TARGET_ASAN
- **Known Issue**: Issue #157 (malformed Base64 length)
- **Reproduction Command**: `./build-asan/deep_fuzzer "/mnt/c/Users/dxksh/Desktop/swa/fastgltf/findings/crashes/crash-015cba103d3994628d29255ce8fcb6a534eb5103"`

## Sanitizer Configuration
- ASan + UBSan (-fsanitize=fuzzer,address,undefined -fno-sanitize-recover=undefined)

## Observed Behavior
Under AddressSanitizer/UBSan, processing the testcase results in termination with SEGV.

## Stack Trace
```text
deep_fuzzer: /mnt/c/Users/dxksh/Desktop/swa/fastgltf/external/fastgltf/include/fastgltf/base64.hpp:53: std::size_t fastgltf::base64::getPadding(const std::string_view): Assertion `string.size() >= 4 && string.size() % 4 == 0' failed.
==15== ERROR: libFuzzer: deadly signal
    #0 0x5a99bd0f30d5 in __sanitizer_print_stack_trace (/mnt/c/Users/dxksh/Desktop/swa/fastgltf/build-asan/deep_fuzzer+0x5a60d5) (BuildId: 9050c160bf041410d83656131643418d8ee3b9e6)
    #1 0x5a99bd04cbec in fuzzer::PrintStackTrace() (/mnt/c/Users/dxksh/Desktop/swa/fastgltf/build-asan/deep_fuzzer+0x4ffbec) (BuildId: 9050c160bf041410d83656131643418d8ee3b9e6)
    #2 0x5a99bd032c77 in fuzzer::Fuzzer::CrashCallback() (/mnt/c/Users/dxksh/Desktop/swa/fastgltf/build-asan/deep_fuzzer+0x4e5c77) (BuildId: 9050c160bf041410d83656131643418d8ee3b9e6)
    #3 0x7e5fdfc4532f  (/lib/x86_64-linux-gnu/libc.so.6+0x4532f) (BuildId: a4a7992a8e66555c8141ab2a08a8465ff6e0ea65)
    #4 0x7e5fdfc9ec0b in pthread_kill (/lib/x86_64-linux-gnu/libc.so.6+0x9ec0b) (BuildId: a4a7992a8e66555c8141ab2a08a8465ff6e0ea65)
    #5 0x7e5fdfc4527d in raise (/lib/x86_64-linux-gnu/libc.so.6+0x4527d) (BuildId: a4a7992a8e66555c8141ab2a08a8465ff6e0ea65)
    #6 0x7e5fdfc288fe in abort (/lib/x86_64-linux-gnu/libc.so.6+0x288fe) (BuildId: a4a7992a8e66555c8141ab2a08a8465ff6e0ea65)
    #7 0x7e5fdfc2881a  (/lib/x86_64-linux-gnu/libc.so.6+0x2881a) (BuildId: a4a7992a8e66555c8141ab2a08a8465ff6e0ea65)
    #8 0x7e5fdfc3b516 in __assert_fail (/lib/x86_64-linux-gnu/libc.so.6+0x3b516) (BuildId: a4a7992a8e66555c8141ab2a08a8465ff6e0ea65)
    #9 0x5a99bd488aa9 in fastgltf::base64::getPadding(std::basic_string_view<char, std::char_traits<char>>) /mnt/c/Users/dxksh/Desktop/swa/fastgltf/external/fastgltf/include/fastgltf/base64.hpp:53:3
    #10 0x5a99bd488aa9 in fastgltf::Parser::decodeDataUri(fastgltf::URIView const&) const /mnt/c/Users/dxksh/Desktop/swa/fastgltf/external/fastgltf/src/fastgltf.cpp:708:17
    #11 0x5a99bd4e7105 in fastgltf::Parser::parseBuffers(simdjson::dom::array&, fastgltf::Asset&) /mnt/c/Users/dxksh/Desktop/swa/fastgltf/external/fastgltf/src/fastgltf.cpp:2032:28
    #12 0x5a99bd4d62df in fastgltf::Parser::parse(simdjson::dom::object, fastgltf::Category) /mnt/c/Users/dxksh/Desktop/swa/fastgltf/external/fastgltf/src/fastgltf.cpp:1586:4
    #13 0x5a99bd563f11 in fastgltf::Parser::loadGltfJson(fastgltf::GltfDataGetter&, std::filesystem::__cxx11::path, fastgltf::Options, fastgltf::Category) /mnt/c/Users/dxksh/Desktop/swa/fastgltf/external/fastgltf/src/fastgltf.cpp:4963:9
    #14 0x5a99bd562a4f in fastgltf::Parser::loadGltf(fastgltf::GltfDataGetter&, std::filesystem::__cxx11::path, fastgltf::Options, fastgltf::Category) /mnt/c/Users/dxksh/Desktop/swa/fastgltf/external/fastgltf/src/fastgltf.cpp:4930:10
    #15 0x5a99bd12944e in LLVMFuzzerTestOneInput /mnt/c/Users/dxksh/Desktop/swa/fastgltf/fuzz/deep_fuzzer.cpp:42:33
    #16 0x5a99bd034244 in fuzzer::Fuzzer::ExecuteCallback(unsigned char const*, unsigned long) (/mnt/c/Users/dxksh/Desktop/swa/fastgltf/build-asan/deep_fuzzer+0x4e7244) (BuildId: 9050c160bf041410d83656131643418d8ee3b9e6)
    #17 0x5a99bd01d376 in fuzzer::RunOneTest(fuzzer::Fuzzer*, char const*, unsigned long) (/mnt/c/Users/dxksh/Desktop/swa/fastgltf/build-asan/deep_fuzzer+0x4d0376) (BuildId: 9050c160bf041410d83656131643418d8ee3b9e6)
    #18 0x5a99bd022e2a in fuzzer::FuzzerDriver(int*, char***, int (*)(unsigned char const*, unsigned long)) (/mnt/c/Users/dxksh/Desktop/swa/fastgltf/build-asan/deep_fuzzer+0x4d5e2a) (BuildId: 9050c160bf041410d83656131643418d8ee3b9e6)
    #19 0x5a99bd04d5e6 in main (/mnt/c/Users/dxksh/Desktop/swa/fastgltf/build-asan/deep_fuzzer+0x5005e6) (BuildId: 9050c160bf041410d83656131643418d8ee3b9e6)
    #20 0x7e5fdfc2a1c9  (/lib/x86_64-linux-gnu/libc.so.6+0x2a1c9) (BuildId: a4a7992a8e66555c8141ab2a08a8465ff6e0ea65)
    #21 0x7e5fdfc2a28a in __libc_start_main (/lib/x86_64-linux-gnu/libc.so.6+0x2a28a) (BuildId: a4a7992a8e66555c8141ab2a08a8465ff6e0ea65)
    #22 0x5a99bd017f44 in _start (/mnt/c/Users/dxksh/Desktop/swa/fastgltf/build-asan/deep_fuzzer+0x4caf44) (BuildId: 9050c160bf041410d83656131643418d8ee3b9e6)

NOTE: libFuzzer has rudimentary signal handlers.
      Combine libFuzzer with AddressSanitizer or similar for better crash reports.
SUMMARY: libFuzzer: deadly signal
```

## Root-Cause Hypothesis
Base64 padding computation assertion failure on malformed length

## Upstream Recommendation
Verify invariant enforcement before direct indexing or component deserialization.
