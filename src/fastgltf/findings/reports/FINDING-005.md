# Vulnerability Report: FINDING-005

- **Summary**: SEGV in fastgltf::Parser::generateMeshIndices
- **Affected fastgltf version**: v0.9.1
- **Commit**: 705564d4d54500ae88befb0db9e361e447923655
- **Environment**: Linux under WSL2 Ubuntu 24.04, Clang 18.1.3
- **Input Size**: 768 bytes
- **Finding Class**: TARGET_ASAN
- **Known Issue**: No
- **Reproduction Command**: `./build-asan/deep_fuzzer "/mnt/c/Users/dxksh/Desktop/swa/fastgltf/findings/crashes/crash-f62d6a273d6377e10310c9d21b9ef9766372987c"`

## Sanitizer Configuration
- ASan + UBSan (-fsanitize=fuzzer,address,undefined -fno-sanitize-recover=undefined)

## Observed Behavior
Under AddressSanitizer/UBSan, processing the testcase results in termination with SEGV.

## Stack Trace
```text
/usr/bin/../lib/gcc/x86_64-linux-gnu/13/../../../../include/c++/13/bits/stl_vector.h:1129:9: runtime error: reference binding to null pointer of type 'fastgltf::Accessor'
    #0 0x5d44e20db642 in std::vector<fastgltf::Accessor, std::allocator<fastgltf::Accessor>>::operator[](unsigned long) /usr/bin/../lib/gcc/x86_64-linux-gnu/13/../../../../include/c++/13/bits/stl_vector.h:1129:2
    #1 0x5d44e20d8385 in fastgltf::Parser::generateMeshIndices(fastgltf::Asset&) const /mnt/c/Users/dxksh/Desktop/swa/fastgltf/external/fastgltf/src/fastgltf.cpp:872:25
    #2 0x5d44e21195db in fastgltf::Parser::parse(simdjson::dom::object, fastgltf::Category) /mnt/c/Users/dxksh/Desktop/swa/fastgltf/external/fastgltf/src/fastgltf.cpp:1626:20
    #3 0x5d44e21a5f11 in fastgltf::Parser::loadGltfJson(fastgltf::GltfDataGetter&, std::filesystem::__cxx11::path, fastgltf::Options, fastgltf::Category) /mnt/c/Users/dxksh/Desktop/swa/fastgltf/external/fastgltf/src/fastgltf.cpp:4963:9
    #4 0x5d44e21a4a4f in fastgltf::Parser::loadGltf(fastgltf::GltfDataGetter&, std::filesystem::__cxx11::path, fastgltf::Options, fastgltf::Category) /mnt/c/Users/dxksh/Desktop/swa/fastgltf/external/fastgltf/src/fastgltf.cpp:4930:10
    #5 0x5d44e1d6b44e in LLVMFuzzerTestOneInput /mnt/c/Users/dxksh/Desktop/swa/fastgltf/fuzz/deep_fuzzer.cpp:42:33
    #6 0x5d44e1c76244 in fuzzer::Fuzzer::ExecuteCallback(unsigned char const*, unsigned long) (/mnt/c/Users/dxksh/Desktop/swa/fastgltf/build-asan/deep_fuzzer+0x4e7244) (BuildId: 9050c160bf041410d83656131643418d8ee3b9e6)
    #7 0x5d44e1c5f376 in fuzzer::RunOneTest(fuzzer::Fuzzer*, char const*, unsigned long) (/mnt/c/Users/dxksh/Desktop/swa/fastgltf/build-asan/deep_fuzzer+0x4d0376) (BuildId: 9050c160bf041410d83656131643418d8ee3b9e6)
    #8 0x5d44e1c64e2a in fuzzer::FuzzerDriver(int*, char***, int (*)(unsigned char const*, unsigned long)) (/mnt/c/Users/dxksh/Desktop/swa/fastgltf/build-asan/deep_fuzzer+0x4d5e2a) (BuildId: 9050c160bf041410d83656131643418d8ee3b9e6)
    #9 0x5d44e1c8f5e6 in main (/mnt/c/Users/dxksh/Desktop/swa/fastgltf/build-asan/deep_fuzzer+0x5005e6) (BuildId: 9050c160bf041410d83656131643418d8ee3b9e6)
    #10 0x7f4109c2a1c9  (/lib/x86_64-linux-gnu/libc.so.6+0x2a1c9) (BuildId: a4a7992a8e66555c8141ab2a08a8465ff6e0ea65)
    #11 0x7f4109c2a28a in __libc_start_main (/lib/x86_64-linux-gnu/libc.so.6+0x2a28a) (BuildId: a4a7992a8e66555c8141ab2a08a8465ff6e0ea65)
    #12 0x5d44e1c59f44 in _start (/mnt/c/Users/dxksh/Desktop/swa/fastgltf/build-asan/deep_fuzzer+0x4caf44) (BuildId: 9050c160bf041410d83656131643418d8ee3b9e6)

SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior /usr/bin/../lib/gcc/x86_64-linux-gnu/13/../../../../include/c++/13/bits/stl_vector.h:1129:9 
==1010== ERROR: libFuzzer: deadly signal
    #0 0x5d44e1d350d5 in __sanitizer_print_stack_trace (/mnt/c/Users/dxksh/Desktop/swa/fastgltf/build-asan/deep_fuzzer+0x5a60d5) (BuildId: 9050c160bf041410d83656131643418d8ee3b9e6)
    #1 0x5d44e1c8ebec in fuzzer::PrintStackTrace() (/mnt/c/Users/dxksh/Desktop/swa/fastgltf/build-asan/deep_fuzzer+0x4ffbec) (BuildId: 9050c160bf041410d83656131643418d8ee3b9e6)
    #2 0x5d44e1c74c77 in fuzzer::Fuzzer::CrashCallback() (/mnt/c/Users/dxksh/Desktop/swa/fastgltf/build-asan/deep_fuzzer+0x4e5c77) (BuildId: 9050c160bf041410d83656131643418d8ee3b9e6)
    #3 0x7f4109c4532f  (/lib/x86_64-linux-gnu/libc.so.6+0x4532f) (BuildId: a4a7992a8e66555c8141ab2a08a8465ff6e0ea65)
    #4 0x7f4109c9ec0b in pthread_kill (/lib/x86_64-linux-gnu/libc.so.6+0x9ec0b) (BuildId: a4a7992a8e66555c8141ab2a08a8465ff6e0ea65)
    #5 0x7f4109c4527d in raise (/lib/x86_64-linux-gnu/libc.so.6+0x4527d) (BuildId: a4a7992a8e66555c8141ab2a08a8465ff6e0ea65)
    #6 0x7f4109c288fe in abort (/lib/x86_64-linux-gnu/libc.so.6+0x288fe) (BuildId: a4a7992a8e66555c8141ab2a08a8465ff6e0ea65)
    #7 0x5d44e1d5090a in __sanitizer::Abort() (/mnt/c/Users/dxksh/Desktop/swa/fastgltf/build-asan/deep_fuzzer+0x5c190a) (BuildId: 9050c160bf041410d83656131643418d8ee3b9e6)
    #8 0x5d44e1d4ea94 in __sanitizer::Die() (/mnt/c/Users/dxksh/Desktop/swa/fastgltf/build-asan/deep_fuzzer+0x5bfa94) (BuildId: 9050c160bf041410d83656131643418d8ee3b9e6)
    #9 0x5d44e1d63a6b in __ubsan::ScopedReport::~ScopedReport() (/mnt/c/Users/dxksh/Desktop/swa/fastgltf/build-asan/deep_fuzzer+0x5d4a6b) (BuildId: 9050c160bf041410d83656131643418d8ee3b9e6)
    #10 0x5d44e1d64496 in handleTypeMismatchImpl(__ubsan::TypeMismatchData*, unsigned long, __ubsan::ReportOptions) ubsan_handlers.cpp.o
    #11 0x5d44e1d6463d in __ubsan_handle_type_mismatch_v1_abort (/mnt/c/Users/dxksh/Desktop/swa/fastgltf/build-asan/deep_fuzzer+0x5d563d) (BuildId: 9050c160bf041410d83656131643418d8ee3b9e6)
    #12 0x5d44e20db642 in std::vector<fastgltf::Accessor, std::allocator<fastgltf::Accessor>>::operator[](unsigned long) /usr/bin/../lib/gcc/x86_64-linux-gnu/13/../../../../include/c++/13/bits/stl_vector.h:1129:2
    #13 0x5d44e20d8385 in fastgltf::Parser::generateMeshIndices(fastgltf::Asset&) const /mnt/c/Users/dxksh/Desktop/swa/fastgltf/external/fastgltf/src/fastgltf.cpp:872:25
    #14 0x5d44e21195db in fastgltf::Parser::parse(simdjson::dom::object, fastgltf::Category) /mnt/c/Users/dxksh/Desktop/swa/fastgltf/external/fastgltf/src/fastgltf.cpp:1626:20
    #15 0x5d44e21a5f11 in fastgltf::Parser::loadGltfJson(fastgltf::GltfDataGetter&, std::filesystem::__cxx11::path, fastgltf::Options, fastgltf::Category) /mnt/c/Users/dxksh/Desktop/swa/fastgltf/external/fastgltf/src/fastgltf.cpp:4963:9
    #16 0x5d44e21a4a4f in fastgltf::Parser::loadGltf(fastgltf::GltfDataGetter&, std::filesystem::__cxx11::path, fastgltf::Options, fastgltf::Category) /mnt/c/Users/dxksh/Desktop/swa/fastgltf/external/fastgltf/src/fastgltf.cpp:4930:10
    #17 0x5d44e1d6b44e in LLVMFuzzerTestOneInput /mnt/c/Users/dxksh/Desktop/swa/fastgltf/fuzz/deep_fuzzer.cpp:42:33
    #18 0x5d44e1c76244 in fuzzer::Fuzzer::ExecuteCallback(unsigned char const*, unsigned long) (/mnt/c/Users/dxksh/Desktop/swa/fastgltf/build-asan/deep_fuzzer+0x4e7244) (BuildId: 9050c160bf041410d83656131643418d8ee3b9e6)
```

## Root-Cause Hypothesis
Heap buffer overflow in generateMeshIndices (POSITION accessor index unvalidated)

## Upstream Recommendation
Verify invariant enforcement before direct indexing or component deserialization.
