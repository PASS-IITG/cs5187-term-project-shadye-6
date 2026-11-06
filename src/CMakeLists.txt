cmake_minimum_required(VERSION 3.20)
project(fastgltf_fuzzer VERSION 1.0.0 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

option(BUILD_FUZZERS "Build libFuzzer targets" ON)
option(BUILD_UNIT_TESTS "Build unit test executables" ON)
option(ENABLE_ASAN "Enable AddressSanitizer and UndefinedBehaviorSanitizer" ON)
option(ENABLE_COVERAGE "Enable LLVM source-based code coverage" OFF)
option(ENABLE_INTEGER_SAN "Enable noisy integer sanitizers" OFF)
option(USE_COVERAGE_ALLOWLIST "Use SanitizerCoverage allowlist for fastgltf" ON)

# Configure subproject fastgltf
set(FASTGLTF_ENABLE_TESTS OFF CACHE BOOL "" FORCE)
set(FASTGLTF_ENABLE_EXAMPLES OFF CACHE BOOL "" FORCE)
set(FASTGLTF_ENABLE_DOCS OFF CACHE BOOL "" FORCE)
add_subdirectory(external/fastgltf)

find_package(nlohmann_json REQUIRED)

set(TARGET_COMPILE_FLAGS)
set(TARGET_LINK_FLAGS)

if (ENABLE_COVERAGE)
    list(APPEND TARGET_COMPILE_FLAGS "-fprofile-instr-generate" "-fcoverage-mapping" "-g")
    list(APPEND TARGET_LINK_FLAGS "-fprofile-instr-generate")
endif()

if (BUILD_FUZZERS)
    list(APPEND TARGET_COMPILE_FLAGS "-fsanitize=fuzzer")
    list(APPEND TARGET_LINK_FLAGS "-fsanitize=fuzzer")

    if (USE_COVERAGE_ALLOWLIST)
        set(ALLOWLIST_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake/coverage_allowlist.txt")
        list(APPEND TARGET_COMPILE_FLAGS "-fsanitize-coverage-allowlist=${ALLOWLIST_PATH}")
    endif()
endif()

if (ENABLE_ASAN)
    list(APPEND TARGET_COMPILE_FLAGS "-fsanitize=address,undefined" "-fno-sanitize-recover=undefined" "-fno-omit-frame-pointer" "-g")
    list(APPEND TARGET_LINK_FLAGS "-fsanitize=address,undefined")
endif()

if (ENABLE_INTEGER_SAN)
    list(APPEND TARGET_COMPILE_FLAGS "-fsanitize=signed-integer-overflow,unsigned-integer-overflow,shift,integer-divide-by-zero" "-g")
    list(APPEND TARGET_LINK_FLAGS "-fsanitize=signed-integer-overflow,unsigned-integer-overflow,shift,integer-divide-by-zero")
endif()

# Apply target flags to fastgltf
target_compile_options(fastgltf PRIVATE ${TARGET_COMPILE_FLAGS})
target_link_options(fastgltf PRIVATE ${TARGET_LINK_FLAGS})

# Shared fuzzer support library
add_library(fuzz_support STATIC
    fuzz/telemetry.cpp
    fuzz/mutation_telemetry.cpp
    fuzz/mutation_scheduler.cpp
    fuzz/glb_parser.cpp
    fuzz/reference_decoder.cpp
    fuzz/guarded_buffer_adapter.cpp
    fuzz/asset_exerciser.cpp
    generator/gltf_generator.cpp
)
target_include_directories(fuzz_support PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/fuzz
    ${CMAKE_CURRENT_SOURCE_DIR}/generator
)
target_link_libraries(fuzz_support PUBLIC fastgltf nlohmann_json::nlohmann_json)
target_compile_options(fuzz_support PRIVATE ${TARGET_COMPILE_FLAGS})
target_link_options(fuzz_support PRIVATE ${TARGET_LINK_FLAGS})

# Shared custom mutator library
add_library(fuzz_mutator STATIC
    fuzz/custom_mutator.cpp
)
target_link_libraries(fuzz_mutator PUBLIC fuzz_support)
target_compile_options(fuzz_mutator PRIVATE ${TARGET_COMPILE_FLAGS})
target_link_options(fuzz_mutator PRIVATE ${TARGET_LINK_FLAGS})

# Fuzzing targets (compiled with libFuzzer)
if (BUILD_FUZZERS)
    add_executable(parser_fuzzer fuzz/parser_fuzzer.cpp)
    target_link_libraries(parser_fuzzer PRIVATE fuzz_support fuzz_mutator)
    target_compile_options(parser_fuzzer PRIVATE ${TARGET_COMPILE_FLAGS})
    target_link_options(parser_fuzzer PRIVATE ${TARGET_LINK_FLAGS})

    add_executable(deep_fuzzer fuzz/deep_fuzzer.cpp)
    target_link_libraries(deep_fuzzer PRIVATE fuzz_support fuzz_mutator)
    target_compile_options(deep_fuzzer PRIVATE ${TARGET_COMPILE_FLAGS})
    target_link_options(deep_fuzzer PRIVATE ${TARGET_LINK_FLAGS})

    add_executable(uri_fuzzer fuzz/uri_fuzzer.cpp)
    target_link_libraries(uri_fuzzer PRIVATE fuzz_support)
    target_compile_options(uri_fuzzer PRIVATE ${TARGET_COMPILE_FLAGS})
    target_link_options(uri_fuzzer PRIVATE ${TARGET_LINK_FLAGS})

    add_executable(base64_fuzzer fuzz/base64_fuzzer.cpp)
    target_link_libraries(base64_fuzzer PRIVATE fuzz_support)
    target_compile_options(base64_fuzzer PRIVATE ${TARGET_COMPILE_FLAGS})
    target_link_options(base64_fuzzer PRIVATE ${TARGET_LINK_FLAGS})
endif()

# Standalone coverage runner (when ENABLE_COVERAGE=ON and libFuzzer is OFF)
if (ENABLE_COVERAGE AND NOT BUILD_FUZZERS)
    add_executable(coverage_runner
        fuzz/deep_fuzzer.cpp
        fuzz/coverage_runner.cpp
    )
    target_link_libraries(coverage_runner PRIVATE fuzz_support)
    target_compile_options(coverage_runner PRIVATE ${TARGET_COMPILE_FLAGS})
    target_link_options(coverage_runner PRIVATE ${TARGET_LINK_FLAGS})
endif()

# Unit tests
if (BUILD_UNIT_TESTS)
    set(TEST_FLAGS)
    if (ENABLE_ASAN)
        list(APPEND TEST_FLAGS "-fsanitize=address,undefined" "-g")
    endif()
    if (ENABLE_COVERAGE)
        list(APPEND TEST_FLAGS "-fprofile-instr-generate" "-fcoverage-mapping")
    endif()

    add_executable(scheduler_tests tests/scheduler_tests.cpp)
    target_link_libraries(scheduler_tests PRIVATE fuzz_support fuzz_mutator)
    target_compile_options(scheduler_tests PRIVATE ${TEST_FLAGS})
    target_link_options(scheduler_tests PRIVATE ${TEST_FLAGS})

    add_executable(mutator_tests tests/mutator_tests.cpp)
    target_link_libraries(mutator_tests PRIVATE fuzz_mutator)
    target_compile_options(mutator_tests PRIVATE ${TEST_FLAGS})
    target_link_options(mutator_tests PRIVATE ${TEST_FLAGS})

    add_executable(glb_tests tests/glb_tests.cpp)
    target_link_libraries(glb_tests PRIVATE fuzz_support)
    target_compile_options(glb_tests PRIVATE ${TEST_FLAGS})
    target_link_options(glb_tests PRIVATE ${TEST_FLAGS})

    add_executable(generator_tests tests/generator_tests.cpp)
    target_link_libraries(generator_tests PRIVATE fuzz_support)
    target_compile_options(generator_tests PRIVATE ${TEST_FLAGS})
    target_link_options(generator_tests PRIVATE ${TEST_FLAGS})

    add_executable(adapter_tests tests/adapter_tests.cpp)
    target_link_libraries(adapter_tests PRIVATE fuzz_support)
    target_compile_options(adapter_tests PRIVATE ${TEST_FLAGS})
    target_link_options(adapter_tests PRIVATE ${TEST_FLAGS})

    add_executable(uri_tests tests/uri_tests.cpp)
    target_link_libraries(uri_tests PRIVATE fuzz_support)
    target_compile_options(uri_tests PRIVATE ${TEST_FLAGS})
    target_link_options(uri_tests PRIVATE ${TEST_FLAGS})

    add_executable(base64_tests tests/base64_tests.cpp)
    target_link_libraries(base64_tests PRIVATE fuzz_support)
    target_compile_options(base64_tests PRIVATE ${TEST_FLAGS})
    target_link_options(base64_tests PRIVATE ${TEST_FLAGS})
endif()
