#pragma once

#include <cstddef>
#include <cstdint>
#include <atomic>
#include <unordered_map>
#include <string>
#include <fastgltf/core.hpp>

namespace fastgltf_fuzz {

struct TelemetryStats {
    uint64_t totalExecutions = 0;
    uint64_t parseSuccessCount = 0;
    uint64_t parseFailureCount = 0;
    uint64_t assetsWithBuffers = 0;
    uint64_t assetsWithBufferViews = 0;
    uint64_t assetsWithAccessors = 0;
    uint64_t accessorsExercised = 0;
    uint64_t sparseAccessorsExercised = 0;
    uint64_t extentViolationsDetected = 0;
    uint64_t metamorphicMismatches = 0;
    std::unordered_map<uint64_t, uint64_t> errorCounts; // Error enum value -> count
};

class Telemetry {
public:
    static Telemetry& instance();

    void recordExecution();
    void recordParseSuccess(const fastgltf::Asset& asset);
    void recordParseError(fastgltf::Error error);
    void recordAccessorExercised(bool isSparse);
    void recordExtentViolation();
    void recordMetamorphicMismatch();

    void printSummary(bool force = false);
    std::string dumpJson() const;

private:
    Telemetry();
    ~Telemetry();

    std::atomic<uint64_t> m_totalExecutions{0};
    std::atomic<uint64_t> m_parseSuccessCount{0};
    std::atomic<uint64_t> m_parseFailureCount{0};
    std::atomic<uint64_t> m_assetsWithBuffers{0};
    std::atomic<uint64_t> m_assetsWithBufferViews{0};
    std::atomic<uint64_t> m_assetsWithAccessors{0};
    std::atomic<uint64_t> m_accessorsExercised{0};
    std::atomic<uint64_t> m_sparseAccessorsExercised{0};
    std::atomic<uint64_t> m_extentViolationsDetected{0};
    std::atomic<uint64_t> m_metamorphicMismatches{0};

    // Lightweight atomic array for error enum (enum values 0 to 14)
    static constexpr size_t NUM_ERROR_CODES = 16;
    std::atomic<uint64_t> m_errorCounts[NUM_ERROR_CODES];

    uint64_t m_lastReportedExecutions{0};
};

} // namespace fastgltf_fuzz
