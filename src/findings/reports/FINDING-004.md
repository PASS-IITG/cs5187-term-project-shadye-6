# Vulnerability Report: FINDING-004

- **Summary**: heap-buffer-overflow in fastgltf::Parser::generateMeshIndices
- **Affected fastgltf version**: v0.9.1
- **Commit**: 705564d4d54500ae88befb0db9e361e447923655
- **Environment**: Linux under WSL2 Ubuntu 24.04, Clang 18.1.3
- **Input Size**: 779 bytes
- **Finding Class**: TARGET_ASAN
- **Known Issue**: No
- **Reproduction Command**: `./build-asan/deep_fuzzer "/mnt/c/Users/dxksh/Desktop/swa/fastgltf/findings/crashes/crash-db0170fae561bcc1186860580e462803e93ecac1"`

## Sanitizer Configuration
- ASan + UBSan (-fsanitize=fuzzer,address,undefined -fno-sanitize-recover=undefined)

## Observed Behavior
Under AddressSanitizer/UBSan, processing the testcase results in termination with heap-buffer-overflow.

## Stack Trace
```text
==927==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x513000000408 at pc 0x5d0163f5e486 bp 0x7ffcdef06370 sp 0x7ffcdef06368
READ of size 8 at 0x513000000408 thread T0
    #0 0x5d0163f5e485 in fastgltf::Parser::generateMeshIndices(fastgltf::Asset&) const /mnt/c/Users/dxksh/Desktop/swa/fastgltf/external/fastgltf/src/fastgltf.cpp:872:75
    #1 0x5d0163f9f5db in fastgltf::Parser::parse(simdjson::dom::object, fastgltf::Category) /mnt/c/Users/dxksh/Desktop/swa/fastgltf/external/fastgltf/src/fastgltf.cpp:1626:20
    #2 0x5d016402bf11 in fastgltf::Parser::loadGltfJson(fastgltf::GltfDataGetter&, std::filesystem::__cxx11::path, fastgltf::Options, fastgltf::Category) /mnt/c/Users/dxksh/Desktop/swa/fastgltf/external/fastgltf/src/fastgltf.cpp:4963:9
    #3 0x5d016402aa4f in fastgltf::Parser::loadGltf(fastgltf::GltfDataGetter&, std::filesystem::__cxx11::path, fastgltf::Options, fastgltf::Category) /mnt/c/Users/dxksh/Desktop/swa/fastgltf/external/fastgltf/src/fastgltf.cpp:4930:10
    #4 0x5d0163bf144e in LLVMFuzzerTestOneInput /mnt/c/Users/dxksh/Desktop/swa/fastgltf/fuzz/deep_fuzzer.cpp:42:33
    #5 0x5d0163afc244 in fuzzer::Fuzzer::ExecuteCallback(unsigned char const*, unsigned long) (/mnt/c/Users/dxksh/Desktop/swa/fastgltf/build-asan/deep_fuzzer+0x4e7244) (BuildId: 9050c160bf041410d83656131643418d8ee3b9e6)
    #6 0x5d0163ae5376 in fuzzer::RunOneTest(fuzzer::Fuzzer*, char const*, unsigned long) (/mnt/c/Users/dxksh/Desktop/swa/fastgltf/build-asan/deep_fuzzer+0x4d0376) (BuildId: 9050c160bf041410d83656131643418d8ee3b9e6)
    #7 0x5d0163aeae2a in fuzzer::FuzzerDriver(int*, char***, int (*)(unsigned char const*, unsigned long)) (/mnt/c/Users/dxksh/Desktop/swa/fastgltf/build-asan/deep_fuzzer+0x4d5e2a) (BuildId: 9050c160bf041410d83656131643418d8ee3b9e6)
    #8 0x5d0163b155e6 in main (/mnt/c/Users/dxksh/Desktop/swa/fastgltf/build-asan/deep_fuzzer+0x5005e6) (BuildId: 9050c160bf041410d83656131643418d8ee3b9e6)
    #9 0x7f6eae82a1c9  (/lib/x86_64-linux-gnu/libc.so.6+0x2a1c9) (BuildId: a4a7992a8e66555c8141ab2a08a8465ff6e0ea65)
    #10 0x7f6eae82a28a in __libc_start_main (/lib/x86_64-linux-gnu/libc.so.6+0x2a28a) (BuildId: a4a7992a8e66555c8141ab2a08a8465ff6e0ea65)
    #11 0x5d0163adff44 in _start (/mnt/c/Users/dxksh/Desktop/swa/fastgltf/build-asan/deep_fuzzer+0x4caf44) (BuildId: 9050c160bf041410d83656131643418d8ee3b9e6)

0x513000000408 is located 584 bytes after 384-byte region [0x513000000040,0x5130000001c0)
allocated by thread T0 here:
    #0 0x5d0163bee971 in operator new(unsigned long) (/mnt/c/Users/dxksh/Desktop/swa/fastgltf/build-asan/deep_fuzzer+0x5d9971) (BuildId: 9050c160bf041410d83656131643418d8ee3b9e6)
    #1 0x5d01641c2d72 in std::__new_allocator<fastgltf::Accessor>::allocate(unsigned long, void const*) /usr/bin/../lib/gcc/x86_64-linux-gnu/13/../../../../include/c++/13/bits/new_allocator.h:151:27
    #2 0x5d01641c227b in std::allocator_traits<std::allocator<fastgltf::Accessor>>::allocate(std::allocator<fastgltf::Accessor>&, unsigned long) /usr/bin/../lib/gcc/x86_64-linux-gnu/13/../../../../include/c++/13/bits/alloc_traits.h:482:20
    #3 0x5d01641c227b in std::_Vector_base<fastgltf::Accessor, std::allocator<fastgltf::Accessor>>::_M_allocate(unsigned long) /usr/bin/../lib/gcc/x86_64-linux-gnu/13/../../../../include/c++/13/bits/stl_vector.h:381:20
    #4 0x5d01641ecb6e in fastgltf::Accessor* std::vector<fastgltf::Accessor, std::allocator<fastgltf::Accessor>>::_M_allocate_and_copy<std::move_iterator<fastgltf::Accessor*>>(unsigned long, std::move_iterator<fastgltf::Accessor*>, std::move_iterator<fastgltf::Accessor*>) /usr/bin/../lib/gcc/x86_64-linux-gnu/13/../../../../include/c++/13/bits/stl_vector.h:1619:29
    #5 0x5d0163fd54b0 in std::vector<fastgltf::Accessor, std::allocator<fastgltf::Accessor>>::reserve(unsigned long) /usr/bin/../lib/gcc/x86_64-linux-gnu/13/../../../../include/c++/13/bits/vector.tcc:86:16
    #6 0x5d0163fa69f5 in fastgltf::Parser::parseAccessors(simdjson::dom::array const&, fastgltf::Asset&) /mnt/c/Users/dxksh/Desktop/swa/fastgltf/external/fastgltf/src/fastgltf.cpp:1649:18
    #7 0x5d0163f9e0fa in fastgltf::Parser::parse(simdjson::dom::object, fastgltf::Category) /mnt/c/Users/dxksh/Desktop/swa/fastgltf/external/fastgltf/src/fastgltf.cpp:1584:4
    #8 0x5d016402bf11 in fastgltf::Parser::loadGltfJson(fastgltf::GltfDataGetter&, std::filesystem::__cxx11::path, fastgltf::Options, fastgltf::Category) /mnt/c/Users/dxksh/Desktop/swa/fastgltf/external/fastgltf/src/fastgltf.cpp:4963:9
    #9 0x5d016402aa4f in fastgltf::Parser::loadGltf(fastgltf::GltfDataGetter&, std::filesystem::__cxx11::path, fastgltf::Options, fastgltf::Category) /mnt/c/Users/dxksh/Desktop/swa/fastgltf/external/fastgltf/src/fastgltf.cpp:4930:10
    #10 0x5d0163bf144e in LLVMFuzzerTestOneInput /mnt/c/Users/dxksh/Desktop/swa/fastgltf/fuzz/deep_fuzzer.cpp:42:33
    #11 0x5d0163afc244 in fuzzer::Fuzzer::ExecuteCallback(unsigned char const*, unsigned long) (/mnt/c/Users/dxksh/Desktop/swa/fastgltf/build-asan/deep_fuzzer+0x4e7244) (BuildId: 9050c160bf041410d83656131643418d8ee3b9e6)
    #12 0x5d0163ae5376 in fuzzer::RunOneTest(fuzzer::Fuzzer*, char const*, unsigned long) (/mnt/c/Users/dxksh/Desktop/swa/fastgltf/build-asan/deep_fuzzer+0x4d0376) (BuildId: 9050c160bf041410d83656131643418d8ee3b9e6)
    #13 0x5d0163aeae2a in fuzzer::FuzzerDriver(int*, char***, int (*)(unsigned char const*, unsigned long)) (/mnt/c/Users/dxksh/Desktop/swa/fastgltf/build-asan/deep_fuzzer+0x4d5e2a) (BuildId: 9050c160bf041410d83656131643418d8ee3b9e6)
    #14 0x5d0163b155e6 in main (/mnt/c/Users/dxksh/Desktop/swa/fastgltf/build-asan/deep_fuzzer+0x5005e6) (BuildId: 9050c160bf041410d83656131643418d8ee3b9e6)
    #15 0x7f6eae82a1c9  (/lib/x86_64-linux-gnu/libc.so.6+0x2a1c9) (BuildId: a4a7992a8e66555c8141ab2a08a8465ff6e0ea65)
    #16 0x7f6eae82a28a in __libc_start_main (/lib/x86_64-linux-gnu/libc.so.6+0x2a28a) (BuildId: a4a7992a8e66555c8141ab2a08a8465ff6e0ea65)
    #17 0x5d0163adff44 in _start (/mnt/c/Users/dxksh/Desktop/swa/fastgltf/build-asan/deep_fuzzer+0x4caf44) (BuildId: 9050c160bf041410d83656131643418d8ee3b9e6)
```

## Root-Cause Hypothesis
Heap buffer overflow in generateMeshIndices (POSITION accessor index unvalidated)

## Upstream Recommendation
Verify invariant enforcement before direct indexing or component deserialization.
