# Vulnerability Report: FINDING-006

- **Summary**: heap-buffer-overflow in fastgltf::base64::decode_inplace
- **Affected fastgltf version**: v0.9.1
- **Commit**: 705564d4d54500ae88befb0db9e361e447923655
- **Environment**: Linux under WSL2 Ubuntu 24.04, Clang 18.1.3
- **Input Size**: 801 bytes
- **Finding Class**: TARGET_ASAN
- **Known Issue**: Issue #157 / Base64 LUT bounds
- **Reproduction Command**: `./build-asan/deep_fuzzer "/mnt/c/Users/dxksh/Desktop/swa/fastgltf/findings/crashes/crash-015cba103d3994628d29255ce8fcb6a534eb5103"`

## Sanitizer Configuration
- ASan + UBSan (-fsanitize=fuzzer,address,undefined -fno-sanitize-recover=undefined)

## Observed Behavior
Under AddressSanitizer/UBSan, processing the testcase results in termination with heap-buffer-overflow.

## Stack Trace
```text
==26==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x5060000000b5 at pc 0x58a0e251e3a3 bp 0x7ffebfbaa350 sp 0x7ffebfbaa348
WRITE of size 1 at 0x5060000000b5 thread T0
    #0 0x58a0e251e3a2 in void fastgltf::base64::decode_block<unsigned char*>(std::array<unsigned char, 4ul>&, unsigned char*) /mnt/c/Users/dxksh/Desktop/swa/fastgltf/external/fastgltf/src/base64.cpp:388:13
    #1 0x58a0e251e3a2 in fastgltf::base64::fallback_decode_inplace(std::basic_string_view<char, std::char_traits<char>>, unsigned char*, unsigned long) /mnt/c/Users/dxksh/Desktop/swa/fastgltf/external/fastgltf/src/base64.cpp:400:3
    #2 0x58a0e251f7d1 in std::function<void (std::basic_string_view<char, std::char_traits<char>>, unsigned char*, unsigned long)>::operator()(std::basic_string_view<char, std::char_traits<char>>, unsigned char*, unsigned long) const /usr/bin/../lib/gcc/x86_64-linux-gnu/13/../../../../include/c++/13/bits/std_function.h:591:9
    #3 0x58a0e251f7d1 in fastgltf::base64::decode_inplace(std::basic_string_view<char, std::char_traits<char>>, unsigned char*, unsigned long) /mnt/c/Users/dxksh/Desktop/swa/fastgltf/external/fastgltf/src/base64.cpp:430:9
    #4 0x58a0e23eab9e in fastgltf::Parser::decodeDataUri(fastgltf::URIView const&) const /mnt/c/Users/dxksh/Desktop/swa/fastgltf/external/fastgltf/src/fastgltf.cpp:713:3
    #5 0x58a0e240bfbd in fastgltf::Parser::parseBuffers(simdjson::dom::array&, fastgltf::Asset&) /mnt/c/Users/dxksh/Desktop/swa/fastgltf/external/fastgltf/src/fastgltf.cpp:2032:28
    #6 0x58a0e23ff292 in fastgltf::Parser::parse(simdjson::dom::object, fastgltf::Category) /mnt/c/Users/dxksh/Desktop/swa/fastgltf/external/fastgltf/src/fastgltf.cpp:1586:4
    #7 0x58a0e244b9c4 in fastgltf::Parser::loadGltfJson(fastgltf::GltfDataGetter&, std::filesystem::__cxx11::path, fastgltf::Options, fastgltf::Category) /mnt/c/Users/dxksh/Desktop/swa/fastgltf/external/fastgltf/src/fastgltf.cpp:4963:9
    #8 0x58a0e244abe8 in fastgltf::Parser::loadGltf(fastgltf::GltfDataGetter&, std::filesystem::__cxx11::path, fastgltf::Options, fastgltf::Category) /mnt/c/Users/dxksh/Desktop/swa/fastgltf/external/fastgltf/src/fastgltf.cpp:4930:10
    #9 0x58a0e22df917 in LLVMFuzzerTestOneInput /mnt/c/Users/dxksh/Desktop/swa/fastgltf/fuzz/deep_fuzzer.cpp:42:33
    #10 0x58a0e21ea9c4 in fuzzer::Fuzzer::ExecuteCallback(unsigned char const*, unsigned long) (/mnt/c/Users/dxksh/Desktop/swa/fastgltf/build-release-asan/deep_fuzzer+0x1af9c4) (BuildId: 4647e035cc7155856b9e46bd233dc19e4a8cd09e)
    #11 0x58a0e21d3af6 in fuzzer::RunOneTest(fuzzer::Fuzzer*, char const*, unsigned long) (/mnt/c/Users/dxksh/Desktop/swa/fastgltf/build-release-asan/deep_fuzzer+0x198af6) (BuildId: 4647e035cc7155856b9e46bd233dc19e4a8cd09e)
    #12 0x58a0e21d95aa in fuzzer::FuzzerDriver(int*, char***, int (*)(unsigned char const*, unsigned long)) (/mnt/c/Users/dxksh/Desktop/swa/fastgltf/build-release-asan/deep_fuzzer+0x19e5aa) (BuildId: 4647e035cc7155856b9e46bd233dc19e4a8cd09e)
    #13 0x58a0e2203d66 in main (/mnt/c/Users/dxksh/Desktop/swa/fastgltf/build-release-asan/deep_fuzzer+0x1c8d66) (BuildId: 4647e035cc7155856b9e46bd233dc19e4a8cd09e)
    #14 0x74719582a1c9  (/lib/x86_64-linux-gnu/libc.so.6+0x2a1c9) (BuildId: a4a7992a8e66555c8141ab2a08a8465ff6e0ea65)
    #15 0x74719582a28a in __libc_start_main (/lib/x86_64-linux-gnu/libc.so.6+0x2a28a) (BuildId: a4a7992a8e66555c8141ab2a08a8465ff6e0ea65)
    #16 0x58a0e21ce6c4 in _start (/mnt/c/Users/dxksh/Desktop/swa/fastgltf/build-release-asan/deep_fuzzer+0x1936c4) (BuildId: 4647e035cc7155856b9e46bd233dc19e4a8cd09e)

0x5060000000b5 is located 0 bytes after 53-byte region [0x506000000080,0x5060000000b5)
allocated by thread T0 here:
    #0 0x58a0e22dd211 in operator new[](unsigned long) (/mnt/c/Users/dxksh/Desktop/swa/fastgltf/build-release-asan/deep_fuzzer+0x2a2211) (BuildId: 4647e035cc7155856b9e46bd233dc19e4a8cd09e)
    #1 0x58a0e23eab22 in fastgltf::StaticVector<std::byte>::StaticVector(unsigned long) /mnt/c/Users/dxksh/Desktop/swa/fastgltf/external/fastgltf/include/fastgltf/types.hpp:616:100
    #2 0x58a0e23eab22 in fastgltf::Parser::decodeDataUri(fastgltf::URIView const&) const /mnt/c/Users/dxksh/Desktop/swa/fastgltf/external/fastgltf/src/fastgltf.cpp:709:30
    #3 0x58a0e240bfbd in fastgltf::Parser::parseBuffers(simdjson::dom::array&, fastgltf::Asset&) /mnt/c/Users/dxksh/Desktop/swa/fastgltf/external/fastgltf/src/fastgltf.cpp:2032:28
    #4 0x58a0e23ff292 in fastgltf::Parser::parse(simdjson::dom::object, fastgltf::Category) /mnt/c/Users/dxksh/Desktop/swa/fastgltf/external/fastgltf/src/fastgltf.cpp:1586:4
    #5 0x58a0e244b9c4 in fastgltf::Parser::loadGltfJson(fastgltf::GltfDataGetter&, std::filesystem::__cxx11::path, fastgltf::Options, fastgltf::Category) /mnt/c/Users/dxksh/Desktop/swa/fastgltf/external/fastgltf/src/fastgltf.cpp:4963:9
    #6 0x58a0e244abe8 in fastgltf::Parser::loadGltf(fastgltf::GltfDataGetter&, std::filesystem::__cxx11::path, fastgltf::Options, fastgltf::Category) /mnt/c/Users/dxksh/Desktop/swa/fastgltf/external/fastgltf/src/fastgltf.cpp:4930:10
    #7 0x58a0e22df917 in LLVMFuzzerTestOneInput /mnt/c/Users/dxksh/Desktop/swa/fastgltf/fuzz/deep_fuzzer.cpp:42:33
    #8 0x58a0e21ea9c4 in fuzzer::Fuzzer::ExecuteCallback(unsigned char const*, unsigned long) (/mnt/c/Users/dxksh/Desktop/swa/fastgltf/build-release-asan/deep_fuzzer+0x1af9c4) (BuildId: 4647e035cc7155856b9e46bd233dc19e4a8cd09e)
    #9 0x58a0e21d3af6 in fuzzer::RunOneTest(fuzzer::Fuzzer*, char const*, unsigned long) (/mnt/c/Users/dxksh/Desktop/swa/fastgltf/build-release-asan/deep_fuzzer+0x198af6) (BuildId: 4647e035cc7155856b9e46bd233dc19e4a8cd09e)
    #10 0x58a0e21d95aa in fuzzer::FuzzerDriver(int*, char***, int (*)(unsigned char const*, unsigned long)) (/mnt/c/Users/dxksh/Desktop/swa/fastgltf/build-release-asan/deep_fuzzer+0x19e5aa) (BuildId: 4647e035cc7155856b9e46bd233dc19e4a8cd09e)
    #11 0x58a0e2203d66 in main (/mnt/c/Users/dxksh/Desktop/swa/fastgltf/build-release-asan/deep_fuzzer+0x1c8d66) (BuildId: 4647e035cc7155856b9e46bd233dc19e4a8cd09e)
    #12 0x74719582a1c9  (/lib/x86_64-linux-gnu/libc.so.6+0x2a1c9) (BuildId: a4a7992a8e66555c8141ab2a08a8465ff6e0ea65)
    #13 0x74719582a28a in __libc_start_main (/lib/x86_64-linux-gnu/libc.so.6+0x2a28a) (BuildId: a4a7992a8e66555c8141ab2a08a8465ff6e0ea65)
```

## Root-Cause Hypothesis
Base64 invalid character lookup or buffer bounds

## Upstream Recommendation
Verify invariant enforcement before direct indexing or component deserialization.
