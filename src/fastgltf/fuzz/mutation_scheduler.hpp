#pragma once

#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>
#include <unordered_map>
#include <random>

namespace fastgltf_fuzz {

enum class OperatorFamily : uint8_t {
    Byte = 0,
    StructuredValid = 1,
    InvariantBreaking = 2,
    Procedural = 3,
    Count = 4
};

enum class OperatorId : uint8_t {
    ByteLibFuzzer = 0,
    StructGlbRepair = 1,
    StructJsonAstRepair = 2,
    StructGlbCorrupt = 3,
    StructJsonAstCorrupt = 4,
    StructJsonTextual = 5,
    ProceduralGenerator = 6,
    Count = 7
};

const char* toString(OperatorFamily family);
const char* toString(OperatorId op);
OperatorFamily familyFromString(const std::string& str);
OperatorId operatorFromString(const std::string& str);

struct OperatorInfo {
    OperatorId id;
    OperatorFamily family;
    std::string name;
    std::string description;
    bool enabled = true;
    double baselinePrior = 0.0;
    double minProbability = 0.02;
    double currentProbability = 0.0;
    
    uint64_t attempts = 0;
    double effectiveSamples = 0.0; // N_i discounted
    double discountedReward = 0.0; // R_i discounted
    double lastReward = 0.0;
    uint32_t lastEpochUsed = 0;
};

struct PolicyConfig {
    std::string algorithm = "discounted_ucb";
    uint32_t seed = 20261028;
    bool updateAtEpochBoundary = true;
    double discountFactor = 0.90;
    double ucbExplorationCoefficient = 0.75;
    double familyProbabilityFloor = 0.05;
    double operatorProbabilityFloorWithinFamily = 0.02;
    
    // Initial family priors: 25% byte, 25% structured_valid, 40% invariant_breaking, 10% procedural
    std::vector<double> initialFamilyWeights = {0.25, 0.25, 0.40, 0.10};
    
    // Reward weights
    double rewardCorpusPromotion = 1.0;
    double rewardNovelStageOutcome = 0.5;
    double rewardNovelOracleCandidate = 2.0;
    double rewardNovelCrashCandidate = 1.0;
    
    std::string rewardNormalization = "log1p_per_attempt_and_cost";
    double maxSingleEventReward = 1.0;
    bool ignoreDuplicateKnownCrashReward = true;
    uint64_t minimumAttemptsBeforeTrust = 5;

    // Telemetry configuration
    bool telemetryEnabled = true;
    size_t flushEveryExecutions = 4096;
    size_t maxPendingProvenanceEntries = 100000;
    size_t maxEpochEvents = 500000;
    size_t sampleExecutionTimingDenominator = 64;

    bool loadFromJsonFile(const std::string& path);
    bool loadFromJsonString(const std::string& jsonStr);
    std::string dumpJson() const;
};

class DiscountedUcbScheduler {
public:
    static DiscountedUcbScheduler& instance();

    DiscountedUcbScheduler();

    void reset();
    bool initialize(const PolicyConfig& config);
    bool loadPolicySnapshot(const std::string& jsonPath);
    std::string dumpPolicySnapshot(uint32_t epoch) const;

    bool isAdaptiveActive() const { return m_active; }
    void setActive(bool active) { m_active = active; }

    const PolicyConfig& getConfig() const { return m_config; }

    // Operator selection methods
    OperatorId selectOperator(std::mt19937& rng);
    OperatorFamily selectFamily(std::mt19937& rng);
    OperatorId selectOperatorWithinFamily(OperatorFamily family, std::mt19937& rng);

    // Operator registry queries
    const OperatorInfo& getOperatorInfo(OperatorId id) const {
        return m_operators[static_cast<size_t>(id)];
    }
    double getFamilyProbability(OperatorFamily family) const {
        return m_familyProbabilities[static_cast<size_t>(family)];
    }
    double getOperatorProbability(OperatorId id) const {
        return m_operators[static_cast<size_t>(id)].currentProbability;
    }

    // Set operator enabled / disabled
    void setOperatorEnabled(OperatorId id, bool enabled);
    void setFamilyEnabled(OperatorFamily family, bool enabled);

    // Epoch boundary update using discounted UCB
    void updateEpoch(uint32_t epoch,
                     const std::unordered_map<OperatorId, double>& epochRewards,
                     const std::unordered_map<OperatorId, uint64_t>& epochAttempts);

    // Mathematical utility: normalize probabilities with configured floor
    static void normalizeWithFloors(std::vector<double>& probs,
                                   const std::vector<bool>& enabled,
                                   double floor);

private:
    void recomputeProbabilities();

    bool m_active = false;
    PolicyConfig m_config;
    std::vector<OperatorInfo> m_operators;
    std::vector<double> m_familyProbabilities;
    std::vector<bool> m_familyEnabled;
    uint32_t m_currentEpoch = 0;
};

} // namespace fastgltf_fuzz

