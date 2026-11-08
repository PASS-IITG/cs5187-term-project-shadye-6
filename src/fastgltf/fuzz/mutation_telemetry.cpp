#include "mutation_telemetry.hpp"

#include <nlohmann/json.hpp>
#include <fstream>
#include <cstdlib>

namespace fastgltf_fuzz {

thread_local OperatorId MutationTelemetry::t_currentOperator = OperatorId::ByteLibFuzzer;
thread_local bool MutationTelemetry::t_currentHasProvenance = false;

MutationTelemetry& MutationTelemetry::instance() {
    static MutationTelemetry s_inst;
    return s_inst;
}

MutationTelemetry::MutationTelemetry() {
    m_operatorMetrics.resize(static_cast<size_t>(OperatorId::Count));
    
    // Check environment for snapshot file configuration
    const char* snapEnv = std::getenv("FUZZ_TELEMETRY_SNAPSHOT");
    if (snapEnv && snapEnv[0] != '\0') {
        m_snapshotPath = snapEnv;
    }
    const char* epochEnv = std::getenv("FUZZ_EPOCH_ID");
    if (epochEnv && epochEnv[0] != '\0') {
        m_epochId = static_cast<uint32_t>(std::atoi(epochEnv));
    }
}

MutationTelemetry::~MutationTelemetry() {
    flushSnapshot();
}

void MutationTelemetry::initialize(size_t maxPendingEntries, const std::string& snapshotFile) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_maxPendingEntries = maxPendingEntries > 0 ? maxPendingEntries : 100000;
    if (!snapshotFile.empty()) {
        m_snapshotPath = snapshotFile;
    }
    m_pendingMap.clear();
    m_pendingFifo.clear();
}

void MutationTelemetry::recordMutationEmitted(const uint8_t* payload, size_t payloadSize,
                                             OperatorId op, OperatorFamily fam) {
    if (!payload || payloadSize == 0) return;

    uint64_t hash = fnv1a64(payload, payloadSize);

    std::lock_guard<std::mutex> lock(m_mutex);
    if (m_pendingMap.size() >= m_maxPendingEntries && !m_pendingFifo.empty()) {
        uint64_t oldest = m_pendingFifo.front();
        m_pendingFifo.pop_front();
        m_pendingMap.erase(oldest);
    }

    ProvenanceRecord rec;
    rec.hash = hash;
    rec.size = payloadSize;
    rec.operatorId = op;
    rec.family = fam;
    rec.epochId = m_epochId;

    m_pendingMap[hash] = rec;
    m_pendingFifo.push_back(hash);

    size_t opIdx = static_cast<size_t>(op);
    if (opIdx < m_operatorMetrics.size()) {
        m_operatorMetrics[opIdx].attempts++;
    }

    m_totalMutations++;
}

bool MutationTelemetry::consumeProvenance(const uint8_t* payload, size_t payloadSize,
                                          OperatorId& outOp, OperatorFamily& outFam) {
    if (!payload || payloadSize == 0) {
        m_unmatchedInputs++;
        return false;
    }

    uint64_t hash = fnv1a64(payload, payloadSize);

    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = m_pendingMap.find(hash);
    if (it != m_pendingMap.end() && it->second.size == payloadSize) {
        outOp = it->second.operatorId;
        outFam = it->second.family;
        ProvenanceRecord record = it->second;
        m_pendingMap.erase(it); // Consumed once: prevents stale attribution on corpus replay
        m_totalConsumed++;

        // Record in ledger for corpus promotion matching
        std::string key = formatContentHash(hash, payloadSize);
        if (m_provenanceLedger.size() >= m_maxPendingEntries) {
            if (!m_ledgerFifo.empty()) {
                m_provenanceLedger.erase(m_ledgerFifo.front());
                m_ledgerFifo.pop_front();
            }
        }
        m_provenanceLedger[key] = record;
        m_ledgerFifo.push_back(key);

        return true;
    }

    m_unmatchedInputs++;
    return false;
}

void MutationTelemetry::recordStageFlags(OperatorId op, uint32_t flags) {
    std::lock_guard<std::mutex> lock(m_mutex);
    size_t opIdx = static_cast<size_t>(op);
    if (opIdx >= m_operatorMetrics.size()) return;

    auto& m = m_operatorMetrics[opIdx];
    if (flags & STAGE_PARSED) m.stageParsed++;
    if (flags & STAGE_VALIDATED) m.stageValidated++;
    if (flags & STAGE_MESH_INDICES) m.stageMeshIndices++;
    if (flags & STAGE_ACCESSOR_EXERCISED) m.stageAccessorExercised++;
    if (flags & STAGE_ORACLE_TRIGGERED) m.stageOracleTriggered++;

    m_executionCount++;
}

OperatorMetrics MutationTelemetry::getOperatorMetrics(OperatorId op) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    size_t opIdx = static_cast<size_t>(op);
    if (opIdx < m_operatorMetrics.size()) {
        return m_operatorMetrics[opIdx];
    }
    return OperatorMetrics{};
}

std::string MutationTelemetry::dumpJson() const {
    std::lock_guard<std::mutex> lock(m_mutex);

    nlohmann::json j;
    j["epoch_id"] = m_epochId;
    j["total_mutations_emitted"] = m_totalMutations.load();
    j["total_provenance_consumed"] = m_totalConsumed.load();
    j["unmatched_inputs"] = m_unmatchedInputs.load();
    j["pending_provenance_entries"] = m_pendingMap.size();

    double attributionCoverage = 0.0;
    uint64_t totalTested = m_totalConsumed.load() + m_unmatchedInputs.load();
    if (totalTested > 0) {
        attributionCoverage = static_cast<double>(m_totalConsumed.load()) / static_cast<double>(totalTested);
    }
    j["attribution_coverage"] = attributionCoverage;

    nlohmann::json ops = nlohmann::json::object();
    for (size_t i = 0; i < m_operatorMetrics.size(); ++i) {
        OperatorId id = static_cast<OperatorId>(i);
        const auto& m = m_operatorMetrics[i];
        ops[toString(id)] = {
            {"attempts", m.attempts},
            {"stage_parsed", m.stageParsed},
            {"stage_validated", m.stageValidated},
            {"stage_mesh_indices", m.stageMeshIndices},
            {"stage_accessor_exercised", m.stageAccessorExercised},
            {"stage_oracle_triggered", m.stageOracleTriggered}
        };
    }
    j["operators"] = ops;

    nlohmann::json ledger = nlohmann::json::object();
    for (const auto& kv : m_provenanceLedger) {
        ledger[kv.first] = {
            {"operator", toString(kv.second.operatorId)},
            {"family", toString(kv.second.family)},
            {"epoch", kv.second.epochId}
        };
    }
    j["provenance_ledger"] = ledger;

    return j.dump(2);
}

void MutationTelemetry::flushSnapshot() {
    if (m_snapshotPath.empty()) return;
    std::string jsonStr = dumpJson();
    std::ofstream f(m_snapshotPath, std::ios::trunc);
    if (f.is_open()) {
        f << jsonStr;
    }
}

} // namespace fastgltf_fuzz
