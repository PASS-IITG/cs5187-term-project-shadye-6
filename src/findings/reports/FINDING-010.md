# Vulnerability Report: FINDING-010

- **Summary**: heap-buffer-overflow in fastgltf::StaticVector<std::byte>::StaticVector(fastgltf::StaticVector<std::byte>
- **Affected fastgltf version**: v0.9.1
- **Commit**: 705564d4d54500ae88befb0db9e361e447923655
- **Environment**: Linux under WSL2 Ubuntu 24.04, Clang 18.1.3
- **Input Size**: 769 bytes
- **Finding Class**: TARGET_ASAN
- **Known Issue**: No
- **Reproduction Command**: `./build-asan/deep_fuzzer "/mnt/c/Users/dxksh/Desktop/swa/fastgltf/findings/crashes/crash-90420f4b31ca92784baf1c30805c55f094f63ebb"`

## Sanitizer Configuration
- ASan + UBSan (-fsanitize=fuzzer,address,undefined -fno-sanitize-recover=undefined)

## Observed Behavior
Under AddressSanitizer/UBSan, processing the testcase results in termination with heap-buffer-overflow.

## Stack Trace
```text
==1829==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x502000000093 at pc 0x57a2064a30a0 bp 0x7fffd0e441f0 sp 0x7fffd0e441e8
READ of size 1 at 0x502000000093 thread T0
    #0 0x57a2064a309f in unsigned short fastgltf::internal::deserializeComponent<unsigned short>(std::byte const*, unsigned long) /mnt/c/Users/dxksh/Desktop/swa/fastgltf/external/fastgltf/include/fastgltf/tools.hpp:201:26
    #1 0x57a2065916b9 in unsigned short fastgltf::internal::convertComponent<unsigned short, unsigned short>(std::byte const*, unsigned long, fastgltf::AccessorType, bool) /mnt/c/Users/dxksh/Desktop/swa/fastgltf/external/fastgltf/include/fastgltf/tools.hpp:307:36
    #2 0x57a20658f9d9 in unsigned short fastgltf::internal::convertAccessorElement<unsigned short, unsigned short, 0ul>(std::byte const*, bool, std::integer_sequence<unsigned long, 0ul>) /mnt/c/Users/dxksh/Desktop/swa/fastgltf/external/fastgltf/include/fastgltf/tools.hpp:357:22
    #3 0x57a20658f395 in unsigned short fastgltf::internal::getAccessorElementAt<unsigned short, std::integer_sequence<unsigned long, 0ul>>(fastgltf::ComponentType, std::byte const*, bool) /mnt/c/Users/dxksh/Desktop/swa/fastgltf/external/fastgltf/include/fastgltf/tools.hpp:376:11
    #4 0x57a2065868ce in unsigned short fastgltf::getAccessorElement<unsigned short, fastgltf::DefaultBufferDataAdapter>(fastgltf::Asset const&, fastgltf::Accessor const&, unsigned long, fastgltf::DefaultBufferDataAdapter const&) /mnt/c/Users/dxksh/Desktop/swa/fastgltf/external/fastgltf/include/fastgltf/tools.hpp:667:9
    #5 0x57a206580daf in void fastgltf_fuzz::(anonymous namespace)::testAccessorWithAdapter<unsigned short, fastgltf::DefaultBufferDataAdapter>(fastgltf::Asset const&, fastgltf::Accessor const&, fastgltf::DefaultBufferDataAdapter const&) /mnt/c/Users/dxksh/Desktop/swa/fastgltf/fuzz/asset_exerciser.cpp:80:33
    #6 0x57a20646bfb6 in void fastgltf_fuzz::(anonymous namespace)::exerciseCompatibleAccessor<unsigned short>(fastgltf::Asset const&, fastgltf::Accessor const&) /mnt/c/Users/dxksh/Desktop/swa/fastgltf/fuzz/asset_exerciser.cpp:116:5
    #7 0x57a206468bb7 in fastgltf_fuzz::(anonymous namespace)::dispatchAccessor(fastgltf::Asset const&, fastgltf::Accessor const&) /mnt/c/Users/dxksh/Desktop/swa/fastgltf/fuzz/asset_exerciser.cpp:205:21
    #8 0x57a2064652a3 in fastgltf_fuzz::exerciseAsset(fastgltf::Asset const&) /mnt/c/Users/dxksh/Desktop/swa/fastgltf/fuzz/asset_exerciser.cpp:254:9
    #9 0x57a20641578f in LLVMFuzzerTestOneInput /mnt/c/Users/dxksh/Desktop/swa/fastgltf/fuzz/deep_fuzzer.cpp:53:5
    #10 0x57a206320244 in fuzzer::Fuzzer::ExecuteCallback(unsigned char const*, unsigned long) (/mnt/c/Users/dxksh/Desktop/swa/fastgltf/build-asan/deep_fuzzer+0x4e7244) (BuildId: 71d11a1cb751667da9b211f61748bcd97c6614a3)
    #11 0x57a206309376 in fuzzer::RunOneTest(fuzzer::Fuzzer*, char const*, unsigned long) (/mnt/c/Users/dxksh/Desktop/swa/fastgltf/build-asan/deep_fuzzer+0x4d0376) (BuildId: 71d11a1cb751667da9b211f61748bcd97c6614a3)
    #12 0x57a20630ee2a in fuzzer::FuzzerDriver(int*, char***, int (*)(unsigned char const*, unsigned long)) (/mnt/c/Users/dxksh/Desktop/swa/fastgltf/build-asan/deep_fuzzer+0x4d5e2a) (BuildId: 71d11a1cb751667da9b211f61748bcd97c6614a3)
    #13 0x57a2063395e6 in main (/mnt/c/Users/dxksh/Desktop/swa/fastgltf/build-asan/deep_fuzzer+0x5005e6) (BuildId: 71d11a1cb751667da9b211f61748bcd97c6614a3)
    #14 0x714679e2a1c9  (/lib/x86_64-linux-gnu/libc.so.6+0x2a1c9) (BuildId: a4a7992a8e66555c8141ab2a08a8465ff6e0ea65)
    #15 0x714679e2a28a in __libc_start_main (/lib/x86_64-linux-gnu/libc.so.6+0x2a28a) (BuildId: a4a7992a8e66555c8141ab2a08a8465ff6e0ea65)
    #16 0x57a206303f44 in _start (/mnt/c/Users/dxksh/Desktop/swa/fastgltf/build-asan/deep_fuzzer+0x4caf44) (BuildId: 71d11a1cb751667da9b211f61748bcd97c6614a3)

0x502000000093 is located 0 bytes after 3-byte region [0x502000000090,0x502000000093)
allocated by thread T0 here:
    #0 0x57a206412a91 in operator new[](unsigned long) (/mnt/c/Users/dxksh/Desktop/swa/fastgltf/build-asan/deep_fuzzer+0x5d9a91) (BuildId: 71d11a1cb751667da9b211f61748bcd97c6614a3)
    #1 0x57a206928788 in fastgltf::StaticVector<std::byte>::StaticVector(fastgltf::StaticVector<std::byte> const&) /mnt/c/Users/dxksh/Desktop/swa/fastgltf/external/fastgltf/include/fastgltf/types.hpp:628:18
    #2 0x57a206928385 in std::pair<fastgltf::StaticVector<std::byte>, fastgltf::ComponentType>::pair<fastgltf::StaticVector<std::byte>&, fastgltf::ComponentType, true>(fastgltf::StaticVector<std::byte>&, fastgltf::ComponentType&&) /usr/bin/../lib/gcc/x86_64-linux-gnu/13/../../../../include/c++/13/bits/stl_pair.h:688:4
    #3 0x57a20677ee98 in std::pair<std::__strip_reference_wrapper<std::decay<fastgltf::StaticVector<std::byte>&>::type>::__type, std::__strip_reference_wrapper<std::decay<fastgltf::ComponentType>::type>::__type> std::make_pair<fastgltf::StaticVector<std::byte>&, fastgltf::ComponentType>(fastgltf::StaticVector<std::byte>&, fastgltf::ComponentType&&) /usr/bin/../lib/gcc/x86_64-linux-gnu/13/../../../../include/c++/13/bits/stl_pair.h:927:14
```

## Root-Cause Hypothesis
New potential candidate

## Upstream Recommendation
Verify invariant enforcement before direct byte indexing in accessor tools.
