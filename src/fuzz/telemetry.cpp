#include "telemetry.hpp"
#include <iostream>
#include <fstream>
#include <cstdlib>
#include <sstream>

namespace fastgltf_fuzz {

Telemetry& Telemetry::instance() {
    static Telemetry inst;
    return inst;
}

Telemetry::Telemetry() {
    for (size_t i = 0; i < NUM_ERROR_CODES; ++i) {
        m_errorCounts[i].store(0, std::memory_order_relaxed);
    }
}

Telemetry::~Telemetry() {
    printSummary(true);
}

void Telemetry::recordExecution() {
    uint64_t total = m_totalExecutions.fetch_add(1, std::memory_order_relaxed) + 1;
    // Periodic report every 50,000 runs
    if (total % 50000 == 0) {
        printSummary(false);
    }
}

void Telemetry::recordParseSuccess(const fastgltf::Asset& asset) {
    m_parseSuccessCount.fetch_add(1, std::memory_order_relaxed);
    if (!asset.buffers.empty()) {
        m_assetsWithBuffers.fetch_add(1, std::memory_order_relaxed);
    }
    if (!asset.bufferViews.empty()) {
        m_assetsWithBufferViews.fetch_add(1, std::memory_order_relaxed);
    }
    if (!asset.accessors.empty()) {
        m_assetsWithAccessors.fetch_add(1, std::memory_order_relaxed);
    }
}

void Telemetry::recordParseError(fastgltf::Error error) {
    m_parseFailureCount.fetch_add(1, std::memory_order_relaxed);
    auto code = static_cast<size_t>(error);
    if (code < NUM_ERROR_CODES) {
        m_errorCounts[code].fetch_add(1, std::memory_order_relaxed);
    }
}

void Telemetry::recordAccessorExercised(bool isSparse) {
    m_accessorsExercised.fetch_add(1, std::memory_order_relaxed);
    if (isSparse) {
        m_sparseAccessorsExercised.fetch_add(1, std::memory_order_relaxed);
    }
}

void Telemetry::recordExtentViolation() {
    m_extentViolationsDetected.fetch_add(1, std::memory_order_relaxed);
}

void Telemetry::recordMetamorphicMismatch() {
    m_metamorphicMismatches.fetch_add(1, std::memory_order_relaxed);
}

std::string Telemetry::dumpJson() const {
    std::ostringstream ss;
    ss << "{\n";
    ss << "  \"total_executions\": " << m_totalExecutions.load(std::memory_order_relaxed) << ",\n";
    ss << "  \"parse_success_count\": " << m_parseSuccessCount.load(std::memory_order_relaxed) << ",\n";
    ss << "  \"parse_failure_count\": " << m_parseFailureCount.load(std::memory_order_relaxed) << ",\n";
    ss << "  \"assets_with_buffers\": " << m_assetsWithBuffers.load(std::memory_order_relaxed) << ",\n";
    ss << "  \"assets_with_bufferviews\": " << m_assetsWithBufferViews.load(std::memory_order_relaxed) << ",\n";
    ss << "  \"assets_with_accessors\": " << m_assetsWithAccessors.load(std::memory_order_relaxed) << ",\n";
    ss << "  \"accessors_exercised\": " << m_accessorsExercised.load(std::memory_order_relaxed) << ",\n";
    ss << "  \"sparse_accessors_exercised\": " << m_sparseAccessorsExercised.load(std::memory_order_relaxed) << ",\n";
    ss << "  \"extent_violations_detected\": " << m_extentViolationsDetected.load(std::memory_order_relaxed) << ",\n";
    ss << "  \"metamorphic_mismatches\": " << m_metamorphicMismatches.load(std::memory_order_relaxed) << ",\n";
    ss << "  \"error_breakdown\": {\n";
    bool first = true;
    for (size_t i = 1; i < NUM_ERROR_CODES; ++i) {
        uint64_t count = m_errorCounts[i].load(std::memory_order_relaxed);
        if (count > 0) {
            if (!first) ss << ",\n";
            auto errEnum = static_cast<fastgltf::Error>(i);
            ss << "    \"" << fastgltf::getErrorName(errEnum) << "\": " << count;
            first = false;
        }
    }
    ss << "\n  }\n";
    ss << "}\n";
    return ss.str();
}

void Telemetry::printSummary(bool force) {
    uint64_t current = m_totalExecutions.load(std::memory_order_relaxed);
    if (!force && current == m_lastReportedExecutions) {
        return;
    }
    m_lastReportedExecutions = current;

    const char* logPath = std::getenv("TELEMETRY_LOG");
    if (logPath) {
        std::ofstream ofs(logPath);
        if (ofs.is_open()) {
            ofs << dumpJson();
        }
    }
}

} // namespace fastgltf_fuzz
