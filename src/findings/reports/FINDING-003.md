# Vulnerability Report: FINDING-003

- **Summary**: SEGV in fastgltf::URIView::URIView
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
Under AddressSanitizer/UBSan, processing the testcase results in termination with SEGV.

## Stack Trace
```text
terminate called after throwing an instance of 'std::out_of_range'
  what():  basic_string_view::substr: __pos (which is 18446744073709551615) > __size (which is 97)
==200== ERROR: libFuzzer: deadly signal
    #0 0x5785625780d5 in __sanitizer_print_stack_trace (/mnt/c/Users/dxksh/Desktop/swa/fastgltf/build-asan/deep_fuzzer+0x5a60d5) (BuildId: 9050c160bf041410d83656131643418d8ee3b9e6)
    #1 0x5785624d1bec in fuzzer::PrintStackTrace() (/mnt/c/Users/dxksh/Desktop/swa/fastgltf/build-asan/deep_fuzzer+0x4ffbec) (BuildId: 9050c160bf041410d83656131643418d8ee3b9e6)
    #2 0x5785624b7c77 in fuzzer::Fuzzer::CrashCallback() (/mnt/c/Users/dxksh/Desktop/swa/fastgltf/build-asan/deep_fuzzer+0x4e5c77) (BuildId: 9050c160bf041410d83656131643418d8ee3b9e6)
    #3 0x7e808ec4532f  (/lib/x86_64-linux-gnu/libc.so.6+0x4532f) (BuildId: a4a7992a8e66555c8141ab2a08a8465ff6e0ea65)
    #4 0x7e808ec9ec0b in pthread_kill (/lib/x86_64-linux-gnu/libc.so.6+0x9ec0b) (BuildId: a4a7992a8e66555c8141ab2a08a8465ff6e0ea65)
    #5 0x7e808ec4527d in raise (/lib/x86_64-linux-gnu/libc.so.6+0x4527d) (BuildId: a4a7992a8e66555c8141ab2a08a8465ff6e0ea65)
    #6 0x7e808ec288fe in abort (/lib/x86_64-linux-gnu/libc.so.6+0x288fe) (BuildId: a4a7992a8e66555c8141ab2a08a8465ff6e0ea65)
    #7 0x7e808f0a5ff4  (/lib/x86_64-linux-gnu/libstdc++.so.6+0xa5ff4) (BuildId: 753c6c8608b61d4e67be8f0c890e03e0aa046b8b)
    #8 0x7e808f0bb0d9  (/lib/x86_64-linux-gnu/libstdc++.so.6+0xbb0d9) (BuildId: 753c6c8608b61d4e67be8f0c890e03e0aa046b8b)
    #9 0x7e808f0a5a54 in std::terminate() (/lib/x86_64-linux-gnu/libstdc++.so.6+0xa5a54) (BuildId: 753c6c8608b61d4e67be8f0c890e03e0aa046b8b)
    #10 0x5785625b01cd in __clang_call_terminate (/mnt/c/Users/dxksh/Desktop/swa/fastgltf/build-asan/deep_fuzzer+0x5de1cd) (BuildId: 9050c160bf041410d83656131643418d8ee3b9e6)
    #11 0x5785629020c1 in fastgltf::URIView::URIView(std::basic_string_view<char, std::char_traits<char>>) /mnt/c/Users/dxksh/Desktop/swa/fastgltf/external/fastgltf/src/fastgltf.cpp:397:2
    #12 0x57856296c067 in fastgltf::Parser::parseBuffers(simdjson::dom::array&, fastgltf::Asset&) /mnt/c/Users/dxksh/Desktop/swa/fastgltf/external/fastgltf/src/fastgltf.cpp:2025:12
    #13 0x57856295b2df in fastgltf::Parser::parse(simdjson::dom::object, fastgltf::Category) /mnt/c/Users/dxksh/Desktop/swa/fastgltf/external/fastgltf/src/fastgltf.cpp:1586:4
    #14 0x5785629e8f11 in fastgltf::Parser::loadGltfJson(fastgltf::GltfDataGetter&, std::filesystem::__cxx11::path, fastgltf::Options, fastgltf::Category) /mnt/c/Users/dxksh/Desktop/swa/fastgltf/external/fastgltf/src/fastgltf.cpp:4963:9
    #15 0x5785629e7a4f in fastgltf::Parser::loadGltf(fastgltf::GltfDataGetter&, std::filesystem::__cxx11::path, fastgltf::Options, fastgltf::Category) /mnt/c/Users/dxksh/Desktop/swa/fastgltf/external/fastgltf/src/fastgltf.cpp:4930:10
    #16 0x5785625ae44e in LLVMFuzzerTestOneInput /mnt/c/Users/dxksh/Desktop/swa/fastgltf/fuzz/deep_fuzzer.cpp:42:33
    #17 0x5785624b9244 in fuzzer::Fuzzer::ExecuteCallback(unsigned char const*, unsigned long) (/mnt/c/Users/dxksh/Desktop/swa/fastgltf/build-asan/deep_fuzzer+0x4e7244) (BuildId: 9050c160bf041410d83656131643418d8ee3b9e6)
    #18 0x5785624a2376 in fuzzer::RunOneTest(fuzzer::Fuzzer*, char const*, unsigned long) (/mnt/c/Users/dxksh/Desktop/swa/fastgltf/build-asan/deep_fuzzer+0x4d0376) (BuildId: 9050c160bf041410d83656131643418d8ee3b9e6)
    #19 0x5785624a7e2a in fuzzer::FuzzerDriver(int*, char***, int (*)(unsigned char const*, unsigned long)) (/mnt/c/Users/dxksh/Desktop/swa/fastgltf/build-asan/deep_fuzzer+0x4d5e2a) (BuildId: 9050c160bf041410d83656131643418d8ee3b9e6)
    #20 0x5785624d25e6 in main (/mnt/c/Users/dxksh/Desktop/swa/fastgltf/build-asan/deep_fuzzer+0x5005e6) (BuildId: 9050c160bf041410d83656131643418d8ee3b9e6)
    #21 0x7e808ec2a1c9  (/lib/x86_64-linux-gnu/libc.so.6+0x2a1c9) (BuildId: a4a7992a8e66555c8141ab2a08a8465ff6e0ea65)
    #22 0x7e808ec2a28a in __libc_start_main (/lib/x86_64-linux-gnu/libc.so.6+0x2a28a) (BuildId: a4a7992a8e66555c8141ab2a08a8465ff6e0ea65)
    #23 0x57856249cf44 in _start (/mnt/c/Users/dxksh/Desktop/swa/fastgltf/build-asan/deep_fuzzer+0x4caf44) (BuildId: 9050c160bf041410d83656131643418d8ee3b9e6)

NOTE: libFuzzer has rudimentary signal handlers.
      Combine libFuzzer with AddressSanitizer or similar for better crash reports.
SUMMARY: libFuzzer: deadly signal
```

## Root-Cause Hypothesis
Out of range string_view substr during URIView parsing

## Upstream Recommendation
Verify invariant enforcement before direct indexing or component deserialization.
