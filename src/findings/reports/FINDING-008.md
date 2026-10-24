# Vulnerability Report: FINDING-008

- **Summary**: Unknown in fastgltf_unknown
- **Affected fastgltf version**: v0.9.1
- **Commit**: 705564d4d54500ae88befb0db9e361e447923655
- **Environment**: Linux under WSL2 Ubuntu 24.04, Clang 18.1.3
- **Input Size**: 768 bytes
- **Finding Class**: TARGET_ASAN
- **Known Issue**: No
- **Reproduction Command**: `./build-asan/deep_fuzzer "/mnt/c/Users/dxksh/Desktop/swa/fastgltf/findings/crashes/crash-4ea4a9b110308d313c0ca383bf6271462a926fdf"`

## Sanitizer Configuration
- ASan + UBSan (-fsanitize=fuzzer,address,undefined -fno-sanitize-recover=undefined)

## Observed Behavior
Under AddressSanitizer/UBSan, processing the testcase results in termination with Unknown.

## Stack Trace
```text
==32063==ERROR: AddressSanitizer: heap-use-after-free on address 0x5020000000b4 at pc 0x557d552bd0a0 bp 0x7ffc160606d0 sp 0x7ffc160606c8
READ of size 1 at 0x5020000000b4 thread T0
    #0 0x557d552bd09f in unsigned short fastgltf::internal::deserializeComponent<unsigned short>(std::byte const*, unsigned long) /mnt/c/Users/dxksh/Desktop/swa/fastgltf/external/fastgltf/include/fastgltf/tools.hpp:201:26
    #1 0x557d553ab6b9 in unsigned short fastgltf::internal::convertComponent<unsigned short, unsigned short>(std::byte const*, unsigned long, fastgltf::AccessorType, bool) /mnt/c/Users/dxksh/Desktop/swa/fastgltf/external/fastgltf/include/fastgltf/tools.hpp:307:36
    #2 0x557d553a99d9 in unsigned short fastgltf::internal::convertAccessorElement<unsigned short, unsigned short, 0ul>(std::byte const*, bool, std::integer_sequence<unsigned long, 0ul>) /mnt/c/Users/dxksh/Desktop/swa/fastgltf/external/fastgltf/include/fastgltf/tools.hpp:357:22
    #3 0x557d553a9395 in unsigned short fastgltf::internal::getAccessorElementAt<unsigned short, std::integer_sequence<unsigned long, 0ul>>(fastgltf::ComponentType, std::byte const*, bool) /mnt/c/Users/dxksh/Desktop/swa/fastgltf/external/fastgltf/include/fastgltf/tools.hpp:376:11
    #4 0x557d553a08ce in unsigned short fastgltf::getAccessorElement<unsigned short, fastgltf::DefaultBufferDataAdapter>(fastgltf::Asset const&, fastgltf::Accessor const&, unsigned long, fastgltf::DefaultBufferDataAdapter const&) /mnt/c/Users/dxksh/Desktop/swa/fastgltf/external/fastgltf/include/fastgltf/tools.hpp:667:9
    #5 0x557d5539adaf in void fastgltf_fuzz::(anonymous namespace)::testAccessorWithAdapter<unsigned short, fastgltf::DefaultBufferDataAdapter>(fastgltf::Asset const&, fastgltf::Accessor const&, fastgltf::DefaultBufferDataAdapter const&) /mnt/c/Users/dxksh/Desktop/swa/fastgltf/fuzz/asset_exerciser.cpp:80:33
    #6 0x557d55285fb6 in void fastgltf_fuzz::(anonymous namespace)::exerciseCompatibleAccessor<unsigned short>(fastgltf::Asset const&, fastgltf::Accessor const&) /mnt/c/Users/dxksh/Desktop/swa/fastgltf/fuzz/asset_exerciser.cpp:116:5
    #7 0x557d55282bb7 in fastgltf_fuzz::(anonymous namespace)::dispatchAccessor(fastgltf::Asset const&, fastgltf::Accessor const&) /mnt/c/Users/dxksh/Desktop/swa/fastgltf/fuzz/asset_exerciser.cpp:205:21
    #8 0x557d5527f2a3 in fastgltf_fuzz::exerciseAsset(fastgltf::Asset const&) /mnt/c/Users/dxksh/Desktop/swa/fastgltf/fuzz/asset_exerciser.cpp:254:9
    #9 0x557d5522f78f in LLVMFuzzerTestOneInput /mnt/c/Users/dxksh/Desktop/swa/fastgltf/fuzz/deep_fuzzer.cpp:53:5
    #10 0x557d5513a244 in fuzzer::Fuzzer::ExecuteCallback(unsigned char const*, unsigned long) (/mnt/c/Users/dxksh/Desktop/swa/fastgltf/build-asan/deep_fuzzer+0x4e7244) (BuildId: 71d11a1cb751667da9b211f61748bcd97c6614a3)
    #11 0x557d55123376 in fuzzer::RunOneTest(fuzzer::Fuzzer*, char const*, unsigned long) (/mnt/c/Users/dxksh/Desktop/swa/fastgltf/build-asan/deep_fuzzer+0x4d0376) (BuildId: 71d11a1cb751667da9b211f61748bcd97c6614a3)
    #12 0x557d55128e2a in fuzzer::FuzzerDriver(int*, char***, int (*)(unsigned char const*, unsigned long)) (/mnt/c/Users/dxksh/Desktop/swa/fastgltf/build-asan/deep_fuzzer+0x4d5e2a) (BuildId: 71d11a1cb751667da9b211f61748bcd97c6614a3)
    #13 0x557d551535e6 in main (/mnt/c/Users/dxksh/Desktop/swa/fastgltf/build-asan/deep_fuzzer+0x5005e6) (BuildId: 71d11a1cb751667da9b211f61748bcd97c6614a3)
    #14 0x79407d82a1c9  (/lib/x86_64-linux-gnu/libc.so.6+0x2a1c9) (BuildId: a4a7992a8e66555c8141ab2a08a8465ff6e0ea65)
    #15 0x79407d82a28a in __libc_start_main (/lib/x86_64-linux-gnu/libc.so.6+0x2a28a) (BuildId: a4a7992a8e66555c8141ab2a08a8465ff6e0ea65)
    #16 0x557d5511df44 in _start (/mnt/c/Users/dxksh/Desktop/swa/fastgltf/build-asan/deep_fuzzer+0x4caf44) (BuildId: 71d11a1cb751667da9b211f61748bcd97c6614a3)

0x5020000000b4 is located 4 bytes inside of 8-byte region [0x5020000000b0,0x5020000000b8)
freed by thread T0 here:
    #0 0x557d5522d1f1 in operator delete(void*) (/mnt/c/Users/dxksh/Desktop/swa/fastgltf/build-asan/deep_fuzzer+0x5da1f1) (BuildId: 71d11a1cb751667da9b211f61748bcd97c6614a3)
    #1 0x557d552a1bfa in std::__new_allocator<unsigned long>::deallocate(unsigned long*, unsigned long) /usr/bin/../lib/gcc/x86_64-linux-gnu/13/../../../../include/c++/13/bits/new_allocator.h:172:2
    #2 0x557d552a0de1 in std::allocator_traits<std::allocator<unsigned long>>::deallocate(std::allocator<unsigned long>&, unsigned long*, unsigned long) /usr/bin/../lib/gcc/x86_64-linux-gnu/13/../../../../include/c++/13/bits/alloc_traits.h:517:13
    #3 0x557d552a0de1 in std::_Vector_base<unsigned long, std::allocator<unsigned long>>::_M_deallocate(unsigned long*, unsigned long) /usr/bin/../lib/gcc/x86_64-linux-gnu/13/../../../../include/c++/13/bits/stl_vector.h:390:4
```

## Root-Cause Hypothesis
New potential candidate

## Upstream Recommendation
Verify invariant enforcement before direct byte indexing in accessor tools.
