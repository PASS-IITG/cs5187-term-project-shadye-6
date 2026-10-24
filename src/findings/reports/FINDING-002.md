# Vulnerability Report: FINDING-002

- **Summary**: SEGV in fastgltf::base64::decode_inplace
- **Affected fastgltf version**: v0.9.1
- **Commit**: 705564d4d54500ae88befb0db9e361e447923655
- **Environment**: Linux under WSL2 Ubuntu 24.04, Clang 18.1.3
- **Input Size**: 552 bytes
- **Finding Class**: TARGET_ASAN
- **Known Issue**: Issue #157 / Base64 LUT bounds
- **Reproduction Command**: `./build-asan/deep_fuzzer "/mnt/c/Users/dxksh/Desktop/swa/fastgltf/findings/crashes/crash-12d839744609189422ce51377465b3edb78913f9"`

## Sanitizer Configuration
- ASan + UBSan (-fsanitize=fuzzer,address,undefined -fno-sanitize-recover=undefined)

## Observed Behavior
Under AddressSanitizer/UBSan, processing the testcase results in termination with SEGV.

## Stack Trace
```text
deep_fuzzer: /mnt/c/Users/dxksh/Desktop/swa/fastgltf/external/fastgltf/src/base64.cpp:382: void fastgltf::base64::decode_block(std::array<std::uint8_t, 4> &, Output) [Output = unsigned char *]: Assertion `static_cast<std::size_t>(sixBitChars[i]) < base64lut.size()' failed.
==100== ERROR: libFuzzer: deadly signal
    #0 0x5c39ed3600d5 in __sanitizer_print_stack_trace (/mnt/c/Users/dxksh/Desktop/swa/fastgltf/build-asan/deep_fuzzer+0x5a60d5) (BuildId: 9050c160bf041410d83656131643418d8ee3b9e6)
    #1 0x5c39ed2b9bec in fuzzer::PrintStackTrace() (/mnt/c/Users/dxksh/Desktop/swa/fastgltf/build-asan/deep_fuzzer+0x4ffbec) (BuildId: 9050c160bf041410d83656131643418d8ee3b9e6)
    #2 0x5c39ed29fc77 in fuzzer::Fuzzer::CrashCallback() (/mnt/c/Users/dxksh/Desktop/swa/fastgltf/build-asan/deep_fuzzer+0x4e5c77) (BuildId: 9050c160bf041410d83656131643418d8ee3b9e6)
    #3 0x7214cdc4532f  (/lib/x86_64-linux-gnu/libc.so.6+0x4532f) (BuildId: a4a7992a8e66555c8141ab2a08a8465ff6e0ea65)
    #4 0x7214cdc9ec0b in pthread_kill (/lib/x86_64-linux-gnu/libc.so.6+0x9ec0b) (BuildId: a4a7992a8e66555c8141ab2a08a8465ff6e0ea65)
    #5 0x7214cdc4527d in raise (/lib/x86_64-linux-gnu/libc.so.6+0x4527d) (BuildId: a4a7992a8e66555c8141ab2a08a8465ff6e0ea65)
    #6 0x7214cdc288fe in abort (/lib/x86_64-linux-gnu/libc.so.6+0x288fe) (BuildId: a4a7992a8e66555c8141ab2a08a8465ff6e0ea65)
    #7 0x7214cdc2881a  (/lib/x86_64-linux-gnu/libc.so.6+0x2881a) (BuildId: a4a7992a8e66555c8141ab2a08a8465ff6e0ea65)
    #8 0x7214cdc3b516 in __assert_fail (/lib/x86_64-linux-gnu/libc.so.6+0x3b516) (BuildId: a4a7992a8e66555c8141ab2a08a8465ff6e0ea65)
    #9 0x5c39eda631c4 in void fastgltf::base64::decode_block<unsigned char*>(std::array<unsigned char, 4ul>&, unsigned char*) /mnt/c/Users/dxksh/Desktop/swa/fastgltf/external/fastgltf/src/base64.cpp:382:4
    #10 0x5c39eda631c4 in fastgltf::base64::fallback_decode_inplace(std::basic_string_view<char, std::char_traits<char>>, unsigned char*, unsigned long) /mnt/c/Users/dxksh/Desktop/swa/fastgltf/external/fastgltf/src/base64.cpp:400:3
    #11 0x5c39eda62c3d in fastgltf::base64::avx2_decode_inplace(std::basic_string_view<char, std::char_traits<char>>, unsigned char*, unsigned long) /mnt/c/Users/dxksh/Desktop/swa/fastgltf/external/fastgltf/src/base64.cpp:184:2
    #12 0x5c39eda71a92 in void std::__invoke_impl<void, void (*&)(std::basic_string_view<char, std::char_traits<char>>, unsigned char*, unsigned long), std::basic_string_view<char, std::char_traits<char>>, unsigned char*, unsigned long>(std::__invoke_other, void (*&)(std::basic_string_view<char, std::char_traits<char>>, unsigned char*, unsigned long), std::basic_string_view<char, std::char_traits<char>>&&, unsigned char*&&, unsigned long&&) /usr/bin/../lib/gcc/x86_64-linux-gnu/13/../../../../include/c++/13/bits/invoke.h:61:14
    #13 0x5c39eda7162b in std::enable_if<is_invocable_r_v<void, void (*&)(std::basic_string_view<char, std::char_traits<char>>, unsigned char*, unsigned long), std::basic_string_view<char, std::char_traits<char>>, unsigned char*, unsigned long>, void>::type std::__invoke_r<void, void (*&)(std::basic_string_view<char, std::char_traits<char>>, unsigned char*, unsigned long), std::basic_string_view<char, std::char_traits<char>>, unsigned char*, unsigned long>(void (*&)(std::basic_string_view<char, std::char_traits<char>>, unsigned char*, unsigned long), std::basic_string_view<char, std::char_traits<char>>&&, unsigned char*&&, unsigned long&&) /usr/bin/../lib/gcc/x86_64-linux-gnu/13/../../../../include/c++/13/bits/invoke.h:111:2
    #14 0x5c39eda70deb in std::_Function_handler<void (std::basic_string_view<char, std::char_traits<char>>, unsigned char*, unsigned long), void (*)(std::basic_string_view<char, std::char_traits<char>>, unsigned char*, unsigned long)>::_M_invoke(std::_Any_data const&, std::basic_string_view<char, std::char_traits<char>>&&, unsigned char*&&, unsigned long&&) /usr/bin/../lib/gcc/x86_64-linux-gnu/13/../../../../include/c++/13/bits/std_function.h:290:9
    #15 0x5c39eda67fbb in std::function<void (std::basic_string_view<char, std::char_traits<char>>, unsigned char*, unsigned long)>::operator()(std::basic_string_view<char, std::char_traits<char>>, unsigned char*, unsigned long) const /usr/bin/../lib/gcc/x86_64-linux-gnu/13/../../../../include/c++/13/bits/std_function.h:591:9
    #16 0x5c39eda67a17 in fastgltf::base64::decode_inplace(std::basic_string_view<char, std::char_traits<char>>, unsigned char*, unsigned long) /mnt/c/Users/dxksh/Desktop/swa/fastgltf/external/fastgltf/src/base64.cpp:430:9
    #17 0x5c39ed6f6109 in fastgltf::Parser::decodeDataUri(fastgltf::URIView const&) const /mnt/c/Users/dxksh/Desktop/swa/fastgltf/external/fastgltf/src/fastgltf.cpp:713:3
    #18 0x5c39ed754105 in fastgltf::Parser::parseBuffers(simdjson::dom::array&, fastgltf::Asset&) /mnt/c/Users/dxksh/Desktop/swa/fastgltf/external/fastgltf/src/fastgltf.cpp:2032:28
    #19 0x5c39ed7432df in fastgltf::Parser::parse(simdjson::dom::object, fastgltf::Category) /mnt/c/Users/dxksh/Desktop/swa/fastgltf/external/fastgltf/src/fastgltf.cpp:1586:4
    #20 0x5c39ed7d0f11 in fastgltf::Parser::loadGltfJson(fastgltf::GltfDataGetter&, std::filesystem::__cxx11::path, fastgltf::Options, fastgltf::Category) /mnt/c/Users/dxksh/Desktop/swa/fastgltf/external/fastgltf/src/fastgltf.cpp:4963:9
    #21 0x5c39ed7cfa4f in fastgltf::Parser::loadGltf(fastgltf::GltfDataGetter&, std::filesystem::__cxx11::path, fastgltf::Options, fastgltf::Category) /mnt/c/Users/dxksh/Desktop/swa/fastgltf/external/fastgltf/src/fastgltf.cpp:4930:10
    #22 0x5c39ed39644e in LLVMFuzzerTestOneInput /mnt/c/Users/dxksh/Desktop/swa/fastgltf/fuzz/deep_fuzzer.cpp:42:33
    #23 0x5c39ed2a1244 in fuzzer::Fuzzer::ExecuteCallback(unsigned char const*, unsigned long) (/mnt/c/Users/dxksh/Desktop/swa/fastgltf/build-asan/deep_fuzzer+0x4e7244) (BuildId: 9050c160bf041410d83656131643418d8ee3b9e6)
    #24 0x5c39ed28a376 in fuzzer::RunOneTest(fuzzer::Fuzzer*, char const*, unsigned long) (/mnt/c/Users/dxksh/Desktop/swa/fastgltf/build-asan/deep_fuzzer+0x4d0376) (BuildId: 9050c160bf041410d83656131643418d8ee3b9e6)
    #25 0x5c39ed28fe2a in fuzzer::FuzzerDriver(int*, char***, int (*)(unsigned char const*, unsigned long)) (/mnt/c/Users/dxksh/Desktop/swa/fastgltf/build-asan/deep_fuzzer+0x4d5e2a) (BuildId: 9050c160bf041410d83656131643418d8ee3b9e6)
    #26 0x5c39ed2ba5e6 in main (/mnt/c/Users/dxksh/Desktop/swa/fastgltf/build-asan/deep_fuzzer+0x5005e6) (BuildId: 9050c160bf041410d83656131643418d8ee3b9e6)
    #27 0x7214cdc2a1c9  (/lib/x86_64-linux-gnu/libc.so.6+0x2a1c9) (BuildId: a4a7992a8e66555c8141ab2a08a8465ff6e0ea65)
    #28 0x7214cdc2a28a in __libc_start_main (/lib/x86_64-linux-gnu/libc.so.6+0x2a28a) (BuildId: a4a7992a8e66555c8141ab2a08a8465ff6e0ea65)
    #29 0x5c39ed284f44 in _start (/mnt/c/Users/dxksh/Desktop/swa/fastgltf/build-asan/deep_fuzzer+0x4caf44) (BuildId: 9050c160bf041410d83656131643418d8ee3b9e6)

NOTE: libFuzzer has rudimentary signal handlers.
      Combine libFuzzer with AddressSanitizer or similar for better crash reports.
SUMMARY: libFuzzer: deadly signal
```

## Root-Cause Hypothesis
Base64 invalid character lookup or buffer bounds

## Upstream Recommendation
Verify invariant enforcement before direct indexing or component deserialization.
