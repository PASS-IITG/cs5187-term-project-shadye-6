#pragma once

#include "hash_util.hpp"
#include "mutation_scheduler.hpp"

#include <cstdint>
#include <cstddef>
#include <string>
#include <unordered_map>
#include <deque>
#include <mutex>
#include <atomic>

namespace fastgltf_fuzz {

// Stage flags representing input penetration depth
enum StageFlag : uint32_t {
    STAGE_NONE               = 0,
    STAGE_PARSED             = 1 << 0,
    STAGE_VALIDATED          = 1 << 1,
    STAGE_MESH_INDICES       = 1 << 2,
    STAGE_ACCESSOR_EXERCISED = 1 << 3,
    STAGE_ORACLE_TRIGGERED   = 1 << 4
};

struct ProvenanceRecord {
    uint64_t hash = 0;
    size_t size = 0;
    OperatorId operatorId = OperatorId::ByteLibFuzzer;
    OperatorFamily family = OperatorFamily::Byte;
    uint32_t epochId = 0;
};

struct OperatorMetrics {
    uint64_t attempts = 0;
    uint64_t stageParsed = 0;
    uint64_t stageValidated = 0;
    uint64_t stageMeshIndices = 0;
    uint64_t stageAccessorExercised = 0;
    uint64_t stageOracleTriggered = 0;
};

class MutationTelemetry {
public:
    static MutationTelemetry& instance();

    MutationTelemetry();
    ~MutationTelemetry();

    void initialize(size_t maxPendingEntries, const std::string& snapshotFile = "");
    void setEpochId(uint32_t epoch) { m_epochId = epoch; }
    uint32_t getEpochId() const { return m_epochId; }

    // Called by LLVMFuzzerCustomMutator when a new payload is emitted
    void recordMutationEmitted(const uint8_t* payload, size_t payloadSize,
                               OperatorId op, OperatorFamily fam);

    // Called by LLVMFuzzerTestOneInput on input receipt
    // Returns true if matched against a pending provenance entry and marks it consumed
    bool consumeProvenance(const uint8_t* payload, size_t payloadSize,
                           OperatorId& outOp, OperatorFamily& outFam);

    // Called as the input completes pipeline stages
    void recordStageFlags(OperatorId op, uint32_t flags);

    // Snapshot serialization
    void flushSnapshot();
    std::string dumpJson() const;

    // Queries
    uint64_t getTotalMutations() const { return m_totalMutations.load(); }
    uint64_t getTotalConsumed() const { return m_totalConsumed.load(); }
    uint64_t getUnmatchedInputs() const { return m_unmatchedInputs.load(); }
    OperatorMetrics getOperatorMetrics(OperatorId op) const;

private:
    mutable std::mutex m_mutex;
    uint32_t m_epochId = 0;
    size_t m_maxPendingEntries = 100000;
    std::string m_snapshotPath;

    // Fast lookup map: 64-bit hash -> deque iterator or entry
    // Keyed by hash; collision-checked by size
    std::unordered_map<uint64_t, ProvenanceRecord> m_pendingMap;
    std::deque<uint64_t> m_pendingFifo; // Bounded FIFO eviction order

    // Consumed provenance ledger for epoch promotion matching
    // Keyed by formatContentHash (hex:size)
    std::unordered_map<std::string, ProvenanceRecord> m_provenanceLedger;
    std::deque<std::string> m_ledgerFifo;

    std::vector<OperatorMetrics> m_operatorMetrics;

    std::atomic<uint64_t> m_totalMutations{0};
    std::atomic<uint64_t> m_totalConsumed{0};
    std::atomic<uint64_t> m_unmatchedInputs{0};
    std::atomic<uint64_t> m_executionCount{0};

    // Current input context for stage recording
    thread_local static OperatorId t_currentOperator;
    thread_local static bool t_currentHasProvenance;
};

// RAII helper to record stage flags during fuzz target execution
class StageRecorder {
public:
    explicit StageRecorder(OperatorId op, bool hasProvenance)
        : m_op(op), m_hasProvenance(hasProvenance), m_flags(STAGE_NONE) {}

    ~StageRecorder() {
        if (m_hasProvenance && m_flags != STAGE_NONE) {
            MutationTelemetry::instance().recordStageFlags(m_op, m_flags);
        }
    }

    void addFlag(StageFlag flag) {
        m_flags |= static_cast<uint32_t>(flag);
    }

private:
    OperatorId m_op;
    bool m_hasProvenance;
    uint32_t m_flags;
};

} // namespace fastgltf_fuzz
