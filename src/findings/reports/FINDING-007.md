# Vulnerability Report: FINDING-007

- **Summary**: exception:std::out_of_range in fastgltf::Parser::parseBuffers
- **Affected fastgltf version**: v0.9.1
- **Commit**: 705564d4d54500ae88befb0db9e361e447923655
- **Environment**: Linux under WSL2 Ubuntu 24.04, Clang 18.1.3
- **Input Size**: 796 bytes
- **Finding Class**: TARGET_ASAN
- **Known Issue**: No
- **Reproduction Command**: `./build-asan/deep_fuzzer "/mnt/c/Users/dxksh/Desktop/swa/fastgltf/findings/crashes/crash-2b6dc55207cec473484c531531748959eeead0c2"`

## Sanitizer Configuration
- ASan + UBSan (-fsanitize=fuzzer,address,undefined -fno-sanitize-recover=undefined)

## Observed Behavior
Under AddressSanitizer/UBSan, processing the testcase results in termination with exception:std::out_of_range.

## Stack Trace
```text
terminate called after throwing an instance of 'std::out_of_range'
  what():  basic_string_view::substr: __pos (which is 18446744073709551615) > __size (which is 97)
==226== ERROR: libFuzzer: deadly signal
    #0 0x5b95c856b855 in __sanitizer_print_stack_trace (/mnt/c/Users/dxksh/Desktop/swa/fastgltf/build-release-asan/deep_fuzzer+0x26e855) (BuildId: 4647e035cc7155856b9e46bd233dc19e4a8cd09e)
    #1 0x5b95c84c536c in fuzzer::PrintStackTrace() (/mnt/c/Users/dxksh/Desktop/swa/fastgltf/build-release-asan/deep_fuzzer+0x1c836c) (BuildId: 4647e035cc7155856b9e46bd233dc19e4a8cd09e)
    #2 0x5b95c84ab3f7 in fuzzer::Fuzzer::CrashCallback() (/mnt/c/Users/dxksh/Desktop/swa/fastgltf/build-release-asan/deep_fuzzer+0x1ae3f7) (BuildId: 4647e035cc7155856b9e46bd233dc19e4a8cd09e)
    #3 0x73fa9a04532f  (/lib/x86_64-linux-gnu/libc.so.6+0x4532f) (BuildId: a4a7992a8e66555c8141ab2a08a8465ff6e0ea65)
    #4 0x73fa9a09ec0b in pthread_kill (/lib/x86_64-linux-gnu/libc.so.6+0x9ec0b) (BuildId: a4a7992a8e66555c8141ab2a08a8465ff6e0ea65)
    #5 0x73fa9a04527d in raise (/lib/x86_64-linux-gnu/libc.so.6+0x4527d) (BuildId: a4a7992a8e66555c8141ab2a08a8465ff6e0ea65)
    #6 0x73fa9a0288fe in abort (/lib/x86_64-linux-gnu/libc.so.6+0x288fe) (BuildId: a4a7992a8e66555c8141ab2a08a8465ff6e0ea65)
    #7 0x73fa9a4a5ff4  (/lib/x86_64-linux-gnu/libstdc++.so.6+0xa5ff4) (BuildId: 753c6c8608b61d4e67be8f0c890e03e0aa046b8b)
    #8 0x73fa9a4bb0d9  (/lib/x86_64-linux-gnu/libstdc++.so.6+0xbb0d9) (BuildId: 753c6c8608b61d4e67be8f0c890e03e0aa046b8b)
    #9 0x73fa9a4a5a54 in std::terminate() (/lib/x86_64-linux-gnu/libstdc++.so.6+0xa5a54) (BuildId: 753c6c8608b61d4e67be8f0c890e03e0aa046b8b)
    #10 0x5b95c85a1ded in __clang_call_terminate (/mnt/c/Users/dxksh/Desktop/swa/fastgltf/build-release-asan/deep_fuzzer+0x2a4ded) (BuildId: 4647e035cc7155856b9e46bd233dc19e4a8cd09e)
    #11 0x5b95c86cebbb in fastgltf::Parser::parseBuffers(simdjson::dom::array&, fastgltf::Asset&) /mnt/c/Users/dxksh/Desktop/swa/fastgltf/external/fastgltf/src/fastgltf.cpp
    #12 0x5b95c86c1292 in fastgltf::Parser::parse(simdjson::dom::object, fastgltf::Category) /mnt/c/Users/dxksh/Desktop/swa/fastgltf/external/fastgltf/src/fastgltf.cpp:1586:4
    #13 0x5b95c870d9c4 in fastgltf::Parser::loadGltfJson(fastgltf::GltfDataGetter&, std::filesystem::__cxx11::path, fastgltf::Options, fastgltf::Category) /mnt/c/Users/dxksh/Desktop/swa/fastgltf/external/fastgltf/src/fastgltf.cpp:4963:9
    #14 0x5b95c870cbe8 in fastgltf::Parser::loadGltf(fastgltf::GltfDataGetter&, std::filesystem::__cxx11::path, fastgltf::Options, fastgltf::Category) /mnt/c/Users/dxksh/Desktop/swa/fastgltf/external/fastgltf/src/fastgltf.cpp:4930:10
    #15 0x5b95c85a1917 in LLVMFuzzerTestOneInput /mnt/c/Users/dxksh/Desktop/swa/fastgltf/fuzz/deep_fuzzer.cpp:42:33
    #16 0x5b95c84ac9c4 in fuzzer::Fuzzer::ExecuteCallback(unsigned char const*, unsigned long) (/mnt/c/Users/dxksh/Desktop/swa/fastgltf/build-release-asan/deep_fuzzer+0x1af9c4) (BuildId: 4647e035cc7155856b9e46bd233dc19e4a8cd09e)
    #17 0x5b95c8495af6 in fuzzer::RunOneTest(fuzzer::Fuzzer*, char const*, unsigned long) (/mnt/c/Users/dxksh/Desktop/swa/fastgltf/build-release-asan/deep_fuzzer+0x198af6) (BuildId: 4647e035cc7155856b9e46bd233dc19e4a8cd09e)
    #18 0x5b95c849b5aa in fuzzer::FuzzerDriver(int*, char***, int (*)(unsigned char const*, unsigned long)) (/mnt/c/Users/dxksh/Desktop/swa/fastgltf/build-release-asan/deep_fuzzer+0x19e5aa) (BuildId: 4647e035cc7155856b9e46bd233dc19e4a8cd09e)
    #19 0x5b95c84c5d66 in main (/mnt/c/Users/dxksh/Desktop/swa/fastgltf/build-release-asan/deep_fuzzer+0x1c8d66) (BuildId: 4647e035cc7155856b9e46bd233dc19e4a8cd09e)
    #20 0x73fa9a02a1c9  (/lib/x86_64-linux-gnu/libc.so.6+0x2a1c9) (BuildId: a4a7992a8e66555c8141ab2a08a8465ff6e0ea65)
    #21 0x73fa9a02a28a in __libc_start_main (/lib/x86_64-linux-gnu/libc.so.6+0x2a28a) (BuildId: a4a7992a8e66555c8141ab2a08a8465ff6e0ea65)
    #22 0x5b95c84906c4 in _start (/mnt/c/Users/dxksh/Desktop/swa/fastgltf/build-release-asan/deep_fuzzer+0x1936c4) (BuildId: 4647e035cc7155856b9e46bd233dc19e4a8cd09e)

NOTE: libFuzzer has rudimentary signal handlers.
      Combine libFuzzer with AddressSanitizer or similar for better crash reports.
SUMMARY: libFuzzer: deadly signal
```

## Root-Cause Hypothesis
New potential candidate

## Upstream Recommendation
Verify invariant enforcement before direct indexing or component deserialization.
