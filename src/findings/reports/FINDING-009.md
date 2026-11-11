# Vulnerability Report: FINDING-009

- **Summary**: heap-buffer-overflow in fastgltf_unknown
- **Affected fastgltf version**: v0.9.1
- **Commit**: 705564d4d54500ae88befb0db9e361e447923655
- **Environment**: Linux under WSL2 Ubuntu 24.04, Clang 18.1.3
- **Input Size**: 768 bytes
- **Finding Class**: TARGET_ASAN
- **Known Issue**: No
- **Reproduction Command**: `./build-asan/deep_fuzzer "/mnt/c/Users/dxksh/Desktop/swa/fastgltf/findings/crashes/crash-542ef537c612d81696bdd7bb96a2fc14a7142009"`

## Sanitizer Configuration
- ASan + UBSan (-fsanitize=fuzzer,address,undefined -fno-sanitize-recover=undefined)

## Observed Behavior
Under AddressSanitizer/UBSan, processing the testcase results in termination with heap-buffer-overflow.

## Stack Trace
```text
==32168==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x5020000001d1 at pc 0x58ac400d90a0 bp 0x7ffd15698b30 sp 0x7ffd15698b28
READ of size 1 at 0x5020000001d1 thread T0
    #0 0x58ac400d909f in unsigned short fastgltf::internal::deserializeComponent<unsigned short>(std::byte const*, unsigned long) /mnt/c/Users/dxksh/Desktop/swa/fastgltf/external/fastgltf/include/fastgltf/tools.hpp:201:26
    #1 0x58ac401c76b9 in unsigned short fastgltf::internal::convertComponent<unsigned short, unsigned short>(std::byte const*, unsigned long, fastgltf::AccessorType, bool) /mnt/c/Users/dxksh/Desktop/swa/fastgltf/external/fastgltf/include/fastgltf/tools.hpp:307:36
    #2 0x58ac401c59d9 in unsigned short fastgltf::internal::convertAccessorElement<unsigned short, unsigned short, 0ul>(std::byte const*, bool, std::integer_sequence<unsigned long, 0ul>) /mnt/c/Users/dxksh/Desktop/swa/fastgltf/external/fastgltf/include/fastgltf/tools.hpp:357:22
    #3 0x58ac401c5395 in unsigned short fastgltf::internal::getAccessorElementAt<unsigned short, std::integer_sequence<unsigned long, 0ul>>(fastgltf::ComponentType, std::byte const*, bool) /mnt/c/Users/dxksh/Desktop/swa/fastgltf/external/fastgltf/include/fastgltf/tools.hpp:376:11
    #4 0x58ac401d7654 in unsigned short fastgltf::getAccessorElement<unsigned short, fastgltf_fuzz::GuardedBufferDataAdapter>(fastgltf::Asset const&, fastgltf::Accessor const&, unsigned long, fastgltf_fuzz::GuardedBufferDataAdapter const&) /mnt/c/Users/dxksh/Desktop/swa/fastgltf/external/fastgltf/include/fastgltf/tools.hpp:667:9
    #5 0x58ac401b8b14 in void fastgltf_fuzz::(anonymous namespace)::testAccessorWithAdapter<unsigned short, fastgltf_fuzz::GuardedBufferDataAdapter>(fastgltf::Asset const&, fastgltf::Accessor const&, fastgltf_fuzz::GuardedBufferDataAdapter const&) /mnt/c/Users/dxksh/Desktop/swa/fastgltf/fuzz/asset_exerciser.cpp:80:33
    #6 0x58ac400a2097 in void fastgltf_fuzz::(anonymous namespace)::exerciseCompatibleAccessor<unsigned short>(fastgltf::Asset const&, fastgltf::Accessor const&) /mnt/c/Users/dxksh/Desktop/swa/fastgltf/fuzz/asset_exerciser.cpp:120:5
    #7 0x58ac4009ebb7 in fastgltf_fuzz::(anonymous namespace)::dispatchAccessor(fastgltf::Asset const&, fastgltf::Accessor const&) /mnt/c/Users/dxksh/Desktop/swa/fastgltf/fuzz/asset_exerciser.cpp:205:21
    #8 0x58ac4009b2a3 in fastgltf_fuzz::exerciseAsset(fastgltf::Asset const&) /mnt/c/Users/dxksh/Desktop/swa/fastgltf/fuzz/asset_exerciser.cpp:254:9
    #9 0x58ac4004b78f in LLVMFuzzerTestOneInput /mnt/c/Users/dxksh/Desktop/swa/fastgltf/fuzz/deep_fuzzer.cpp:53:5
    #10 0x58ac3ff56244 in fuzzer::Fuzzer::ExecuteCallback(unsigned char const*, unsigned long) (/mnt/c/Users/dxksh/Desktop/swa/fastgltf/build-asan/deep_fuzzer+0x4e7244) (BuildId: 71d11a1cb751667da9b211f61748bcd97c6614a3)
    #11 0x58ac3ff3f376 in fuzzer::RunOneTest(fuzzer::Fuzzer*, char const*, unsigned long) (/mnt/c/Users/dxksh/Desktop/swa/fastgltf/build-asan/deep_fuzzer+0x4d0376) (BuildId: 71d11a1cb751667da9b211f61748bcd97c6614a3)
    #12 0x58ac3ff44e2a in fuzzer::FuzzerDriver(int*, char***, int (*)(unsigned char const*, unsigned long)) (/mnt/c/Users/dxksh/Desktop/swa/fastgltf/build-asan/deep_fuzzer+0x4d5e2a) (BuildId: 71d11a1cb751667da9b211f61748bcd97c6614a3)
    #13 0x58ac3ff6f5e6 in main (/mnt/c/Users/dxksh/Desktop/swa/fastgltf/build-asan/deep_fuzzer+0x5005e6) (BuildId: 71d11a1cb751667da9b211f61748bcd97c6614a3)
    #14 0x7bca4f02a1c9  (/lib/x86_64-linux-gnu/libc.so.6+0x2a1c9) (BuildId: a4a7992a8e66555c8141ab2a08a8465ff6e0ea65)
    #15 0x7bca4f02a28a in __libc_start_main (/lib/x86_64-linux-gnu/libc.so.6+0x2a28a) (BuildId: a4a7992a8e66555c8141ab2a08a8465ff6e0ea65)
    #16 0x58ac3ff39f44 in _start (/mnt/c/Users/dxksh/Desktop/swa/fastgltf/build-asan/deep_fuzzer+0x4caf44) (BuildId: 71d11a1cb751667da9b211f61748bcd97c6614a3)

0x5020000001d1 is located 0 bytes after 1-byte region [0x5020000001d0,0x5020000001d1)
allocated by thread T0 here:
    #0 0x58ac40048971 in operator new(unsigned long) (/mnt/c/Users/dxksh/Desktop/swa/fastgltf/build-asan/deep_fuzzer+0x5d9971) (BuildId: 71d11a1cb751667da9b211f61748bcd97c6614a3)
    #1 0x58ac403903e6 in std::__new_allocator<std::byte>::allocate(unsigned long, void const*) /usr/bin/../lib/gcc/x86_64-linux-gnu/13/../../../../include/c++/13/bits/new_allocator.h:151:27
    #2 0x58ac4038dacb in std::allocator_traits<std::allocator<std::byte>>::allocate(std::allocator<std::byte>&, unsigned long) /usr/bin/../lib/gcc/x86_64-linux-gnu/13/../../../../include/c++/13/bits/alloc_traits.h:482:20
    #3 0x58ac4038dacb in std::_Vector_base<std::byte, std::allocator<std::byte>>::_M_allocate(unsigned long) /usr/bin/../lib/gcc/x86_64-linux-gnu/13/../../../../include/c++/13/bits/stl_vector.h:381:20
```

## Root-Cause Hypothesis
New potential candidate

## Upstream Recommendation
Verify invariant enforcement before direct byte indexing in accessor tools.
