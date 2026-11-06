#include "mutation_scheduler.hpp"

#include <nlohmann/json.hpp>
#include <fstream>
#include <cmath>
#include <algorithm>
#include <numeric>
#include <stdexcept>
#include <iostream>

namespace fastgltf_fuzz {

const char* toString(OperatorFamily family) {
    switch (family) {
        case OperatorFamily::Byte: return "byte";
        case OperatorFamily::StructuredValid: return "structured_valid";
        case OperatorFamily::InvariantBreaking: return "invariant_breaking";
        case OperatorFamily::Procedural: return "procedural";
        default: return "unknown";
    }
}

const char* toString(OperatorId op) {
    switch (op) {
        case OperatorId::ByteLibFuzzer: return "byte_libfuzzer";
        case OperatorId::StructGlbRepair: return "struct_glb_repair";
        case OperatorId::StructJsonAstRepair: return "struct_json_ast_repair";
        case OperatorId::StructGlbCorrupt: return "struct_glb_corrupt";
        case OperatorId::StructJsonAstCorrupt: return "struct_json_ast_corrupt";
        case OperatorId::StructJsonTextual: return "struct_json_textual";
        case OperatorId::ProceduralGenerator: return "procedural_generator";
        default: return "unknown";
    }
}

OperatorFamily familyFromString(const std::string& str) {
    if (str == "byte") return OperatorFamily::Byte;
    if (str == "structured_valid") return OperatorFamily::StructuredValid;
    if (str == "invariant_breaking") return OperatorFamily::InvariantBreaking;
    if (str == "procedural") return OperatorFamily::Procedural;
    throw std::invalid_argument("Unknown OperatorFamily string: " + str);
}

OperatorId operatorFromString(const std::string& str) {
    if (str == "byte_libfuzzer") return OperatorId::ByteLibFuzzer;
    if (str == "struct_glb_repair") return OperatorId::StructGlbRepair;
    if (str == "struct_json_ast_repair") return OperatorId::StructJsonAstRepair;
    if (str == "struct_glb_corrupt") return OperatorId::StructGlbCorrupt;
    if (str == "struct_json_ast_corrupt") return OperatorId::StructJsonAstCorrupt;
    if (str == "struct_json_textual") return OperatorId::StructJsonTextual;
    if (str == "procedural_generator") return OperatorId::ProceduralGenerator;
    throw std::invalid_argument("Unknown OperatorId string: " + str);
}

bool PolicyConfig::loadFromJsonString(const std::string& jsonStr) {
    try {
        auto j = nlohmann::json::parse(jsonStr);

        if (j.contains("seed") && j["seed"].is_number()) {
            seed = j["seed"].get<uint32_t>();
        }

        if (j.contains("adaptive_scheduler") && j["adaptive_scheduler"].is_object()) {
            auto& sched = j["adaptive_scheduler"];
            if (sched.contains("algorithm") && sched["algorithm"].is_string()) {
                algorithm = sched["algorithm"].get<std::string>();
            }
            if (sched.contains("discount_factor") && sched["discount_factor"].is_number()) {
                discountFactor = sched["discount_factor"].get<double>();
            }
            if (sched.contains("ucb_exploration_coefficient") && sched["ucb_exploration_coefficient"].is_number()) {
                ucbExplorationCoefficient = sched["ucb_exploration_coefficient"].get<double>();
            }
            if (sched.contains("family_probability_floor") && sched["family_probability_floor"].is_number()) {
                familyProbabilityFloor = sched["family_probability_floor"].get<double>();
            }
            if (sched.contains("operator_probability_floor_within_family") && sched["operator_probability_floor_within_family"].is_number()) {
                operatorProbabilityFloorWithinFamily = sched["operator_probability_floor_within_family"].get<double>();
            }

            if (sched.contains("initial_family_weights") && sched["initial_family_weights"].is_object()) {
                auto& w = sched["initial_family_weights"];
                if (w.contains("byte")) initialFamilyWeights[0] = w["byte"].get<double>();
                if (w.contains("structured_valid")) initialFamilyWeights[1] = w["structured_valid"].get<double>();
                if (w.contains("invariant_breaking")) initialFamilyWeights[2] = w["invariant_breaking"].get<double>();
                if (w.contains("procedural")) initialFamilyWeights[3] = w["procedural"].get<double>();
            }

            if (sched.contains("reward_weights") && sched["reward_weights"].is_object()) {
                auto& rw = sched["reward_weights"];
                if (rw.contains("corpus_promotion")) rewardCorpusPromotion = rw["corpus_promotion"].get<double>();
                if (rw.contains("novel_stage_outcome")) rewardNovelStageOutcome = rw["novel_stage_outcome"].get<double>();
                if (rw.contains("novel_oracle_candidate")) rewardNovelOracleCandidate = rw["novel_oracle_candidate"].get<double>();
                if (rw.contains("novel_crash_candidate")) rewardNovelCrashCandidate = rw["novel_crash_candidate"].get<double>();
            }

            if (sched.contains("telemetry") && sched["telemetry"].is_object()) {
                auto& tel = sched["telemetry"];
                if (tel.contains("enabled_in_adaptive_mode")) telemetryEnabled = tel["enabled_in_adaptive_mode"].get<bool>();
                if (tel.contains("flush_every_executions")) flushEveryExecutions = tel["flush_every_executions"].get<size_t>();
                if (tel.contains("max_pending_provenance_entries")) maxPendingProvenanceEntries = tel["max_pending_provenance_entries"].get<size_t>();
                if (tel.contains("max_epoch_events")) maxEpochEvents = tel["max_epoch_events"].get<size_t>();
            }
        }
        return true;
    } catch (...) {
        return false;
    }
}

bool PolicyConfig::loadFromJsonFile(const std::string& path) {
    std::ifstream f(path);
    if (!f.is_open()) return false;
    std::string str((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    return loadFromJsonString(str);
}

std::string PolicyConfig::dumpJson() const {
    nlohmann::json j;
    j["schema_version"] = 1;
    j["seed"] = seed;
    j["adaptive_scheduler"]["algorithm"] = algorithm;
    j["adaptive_scheduler"]["discount_factor"] = discountFactor;
    j["adaptive_scheduler"]["ucb_exploration_coefficient"] = ucbExplorationCoefficient;
    j["adaptive_scheduler"]["family_probability_floor"] = familyProbabilityFloor;
    j["adaptive_scheduler"]["operator_probability_floor_within_family"] = operatorProbabilityFloorWithinFamily;
    j["adaptive_scheduler"]["initial_family_weights"] = {
        {"byte", initialFamilyWeights[0]},
        {"structured_valid", initialFamilyWeights[1]},
        {"invariant_breaking", initialFamilyWeights[2]},
        {"procedural", initialFamilyWeights[3]}
    };
    j["adaptive_scheduler"]["reward_weights"] = {
        {"corpus_promotion", rewardCorpusPromotion},
        {"novel_stage_outcome", rewardNovelStageOutcome},
        {"novel_oracle_candidate", rewardNovelOracleCandidate},
        {"novel_crash_candidate", rewardNovelCrashCandidate}
    };
    j["adaptive_scheduler"]["telemetry"] = {
        {"enabled_in_adaptive_mode", telemetryEnabled},
        {"flush_every_executions", flushEveryExecutions},
        {"max_pending_provenance_entries", maxPendingProvenanceEntries},
        {"max_epoch_events", maxEpochEvents}
    };
    return j.dump(2);
}

DiscountedUcbScheduler& DiscountedUcbScheduler::instance() {
    static DiscountedUcbScheduler s_inst;
    return s_inst;
}

DiscountedUcbScheduler::DiscountedUcbScheduler() {
    reset();
}

void DiscountedUcbScheduler::reset() {
    m_active = false;
    m_currentEpoch = 0;
    m_familyProbabilities = {0.25, 0.25, 0.40, 0.10};
    m_familyEnabled = {true, true, true, true};

    m_operators.clear();
    m_operators.resize(static_cast<size_t>(OperatorId::Count));

    auto reg = [this](OperatorId id, OperatorFamily fam, const char* name, const char* desc, double prior) {
        size_t idx = static_cast<size_t>(id);
        m_operators[idx].id = id;
        m_operators[idx].family = fam;
        m_operators[idx].name = name;
        m_operators[idx].description = desc;
        m_operators[idx].enabled = true;
        m_operators[idx].baselinePrior = prior;
        m_operators[idx].minProbability = m_config.operatorProbabilityFloorWithinFamily;
        m_operators[idx].currentProbability = prior;
    };

    // Family 0: Byte (100% of family)
    reg(OperatorId::ByteLibFuzzer, OperatorFamily::Byte, "byte_libfuzzer",
        "Raw libFuzzer byte mutation fallback", 1.0);

    // Family 1: StructuredValid (split 50% / 50% within family)
    reg(OperatorId::StructGlbRepair, OperatorFamily::StructuredValid, "struct_glb_repair",
        "GLB container chunk mutation with structural repair", 0.50);
    reg(OperatorId::StructJsonAstRepair, OperatorFamily::StructuredValid, "struct_json_ast_repair",
        "JSON AST mutation with repair=true", 0.50);

    // Family 2: InvariantBreaking (split 35% / 50% / 15% within family)
    reg(OperatorId::StructGlbCorrupt, OperatorFamily::InvariantBreaking, "struct_glb_corrupt",
        "GLB container mutation with invariant corruption", 0.35);
    reg(OperatorId::StructJsonAstCorrupt, OperatorFamily::InvariantBreaking, "struct_json_ast_corrupt",
        "JSON AST mutation with repair=false", 0.50);
    reg(OperatorId::StructJsonTextual, OperatorFamily::InvariantBreaking, "struct_json_textual",
        "Raw textual token injection on unparseable JSON", 0.15);

    // Family 3: Procedural (100% of family)
    reg(OperatorId::ProceduralGenerator, OperatorFamily::Procedural, "procedural_generator",
        "Algorithmic synthesis of fresh glTF/GLB models", 1.0);

    recomputeProbabilities();
}

bool DiscountedUcbScheduler::initialize(const PolicyConfig& config) {
    m_config = config;
    reset();
    m_familyProbabilities = config.initialFamilyWeights;
    recomputeProbabilities();
    m_active = true;
    return true;
}

void DiscountedUcbScheduler::setOperatorEnabled(OperatorId id, bool enabled) {
    m_operators[static_cast<size_t>(id)].enabled = enabled;
    recomputeProbabilities();
}

void DiscountedUcbScheduler::setFamilyEnabled(OperatorFamily family, bool enabled) {
    m_familyEnabled[static_cast<size_t>(family)] = enabled;
    recomputeProbabilities();
}

void DiscountedUcbScheduler::normalizeWithFloors(std::vector<double>& probs,
                                               const std::vector<bool>& enabled,
                                               double floor) {
    size_t count = probs.size();
    if (count == 0) return;

    size_t enabledCount = 0;
    for (size_t i = 0; i < count; ++i) {
        if (enabled[i]) ++enabledCount;
    }

    if (enabledCount == 0) {
        std::fill(probs.begin(), probs.end(), 0.0);
        return;
    }

    // If floor * enabledCount >= 1.0, allocate uniform distribution
    if (floor * static_cast<double>(enabledCount) >= 1.0) {
        double uniform = 1.0 / static_cast<double>(enabledCount);
        for (size_t i = 0; i < count; ++i) {
            probs[i] = enabled[i] ? uniform : 0.0;
        }
        return;
    }

    double reservedMass = floor * static_cast<double>(enabledCount);
    double remainingMass = 1.0 - reservedMass;

    double positiveSum = 0.0;
    for (size_t i = 0; i < count; ++i) {
        if (enabled[i]) {
            probs[i] = std::max(0.0, probs[i]);
            positiveSum += probs[i];
        } else {
            probs[i] = 0.0;
        }
    }

    if (positiveSum > 1e-12) {
        for (size_t i = 0; i < count; ++i) {
            if (enabled[i]) {
                probs[i] = floor + (probs[i] / positiveSum) * remainingMass;
            }
        }
    } else {
        double uniformShare = remainingMass / static_cast<double>(enabledCount);
        for (size_t i = 0; i < count; ++i) {
            if (enabled[i]) {
                probs[i] = floor + uniformShare;
            }
        }
    }
}

void DiscountedUcbScheduler::recomputeProbabilities() {
    // 1. Normalize family probabilities
    normalizeWithFloors(m_familyProbabilities, m_familyEnabled, m_config.familyProbabilityFloor);

    // 2. Normalize operators within each family
    for (size_t f = 0; f < static_cast<size_t>(OperatorFamily::Count); ++f) {
        std::vector<size_t> memberIndices;
        std::vector<double> memberProbs;
        std::vector<bool> memberEnabled;

        for (size_t i = 0; i < m_operators.size(); ++i) {
            if (static_cast<size_t>(m_operators[i].family) == f) {
                memberIndices.push_back(i);
                memberProbs.push_back(m_operators[i].currentProbability);
                memberEnabled.push_back(m_operators[i].enabled && m_familyEnabled[f]);
            }
        }

        normalizeWithFloors(memberProbs, memberEnabled, m_config.operatorProbabilityFloorWithinFamily);

        for (size_t idx = 0; idx < memberIndices.size(); ++idx) {
            m_operators[memberIndices[idx]].currentProbability = memberProbs[idx];
        }
    }
}

void DiscountedUcbScheduler::updateEpoch(uint32_t epoch,
                                        const std::unordered_map<OperatorId, double>& epochRewards,
                                        const std::unordered_map<OperatorId, uint64_t>& epochAttempts) {
    m_currentEpoch = epoch;
    double gamma = m_config.discountFactor;
    double c = m_config.ucbExplorationCoefficient;

    // Apply exponential discounting and incorporate new observations
    double totalDiscountedAttempts = 0.0;
    for (auto& op : m_operators) {
        uint64_t attemptsNow = 0;
        auto itA = epochAttempts.find(op.id);
        if (itA != epochAttempts.end()) attemptsNow = itA->second;

        double rewardNow = 0.0;
        auto itR = epochRewards.find(op.id);
        if (itR != epochRewards.end()) rewardNow = itR->second;

        op.attempts += attemptsNow;
        op.effectiveSamples = gamma * op.effectiveSamples + static_cast<double>(attemptsNow);
        op.discountedReward = gamma * op.discountedReward + rewardNow;
        op.lastReward = rewardNow;
        if (attemptsNow > 0) op.lastEpochUsed = epoch;

        totalDiscountedAttempts += op.effectiveSamples;
    }

    // Compute UCB scores for each operator
    std::vector<double> opScores(m_operators.size(), 0.0);
    for (size_t i = 0; i < m_operators.size(); ++i) {
        auto& op = m_operators[i];
        if (!op.enabled) {
            opScores[i] = 0.0;
            continue;
        }

        double meanReward = (op.effectiveSamples > 1e-6)
            ? (op.discountedReward / op.effectiveSamples)
            : op.baselinePrior;

        double exploration = c * std::sqrt(std::log(totalDiscountedAttempts + 1.0) / (op.effectiveSamples + 0.1));
        opScores[i] = meanReward + exploration;
    }

    // Assign raw scores to operator probability slots for normalization
    for (size_t i = 0; i < m_operators.size(); ++i) {
        m_operators[i].currentProbability = opScores[i];
    }

    // Compute family UCB score as the average/sum of member operator scores
    for (size_t f = 0; f < static_cast<size_t>(OperatorFamily::Count); ++f) {
        double famScore = 0.0;
        size_t count = 0;
        for (const auto& op : m_operators) {
            if (static_cast<size_t>(op.family) == f && op.enabled) {
                famScore += op.currentProbability;
                ++count;
            }
        }
        m_familyProbabilities[f] = (count > 0) ? (famScore / static_cast<double>(count)) : 0.0;
    }

    // Re-normalize family and operator probabilities enforcing minimum floors
    recomputeProbabilities();
}

OperatorFamily DiscountedUcbScheduler::selectFamily(std::mt19937& rng) {
    std::uniform_real_distribution<double> dist(0.0, 1.0);
    double r = dist(rng);
    double accum = 0.0;
    for (size_t f = 0; f < m_familyProbabilities.size(); ++f) {
        if (!m_familyEnabled[f]) continue;
        accum += m_familyProbabilities[f];
        if (r <= accum) {
            return static_cast<OperatorFamily>(f);
        }
    }
    // Fallback to first enabled family
    for (size_t f = 0; f < m_familyEnabled.size(); ++f) {
        if (m_familyEnabled[f]) return static_cast<OperatorFamily>(f);
    }
    return OperatorFamily::Byte;
}

OperatorId DiscountedUcbScheduler::selectOperatorWithinFamily(OperatorFamily family, std::mt19937& rng) {
    std::vector<OperatorId> candidates;
    std::vector<double> probs;
    for (const auto& op : m_operators) {
        if (op.family == family && op.enabled) {
            candidates.push_back(op.id);
            probs.push_back(op.currentProbability);
        }
    }

    if (candidates.empty()) {
        return OperatorId::ByteLibFuzzer;
    }

    double total = std::accumulate(probs.begin(), probs.end(), 0.0);
    if (total <= 1e-12) {
        return candidates[rng() % candidates.size()];
    }

    std::uniform_real_distribution<double> dist(0.0, total);
    double r = dist(rng);
    double accum = 0.0;
    for (size_t i = 0; i < candidates.size(); ++i) {
        accum += probs[i];
        if (r <= accum) {
            return candidates[i];
        }
    }
    return candidates.back();
}

OperatorId DiscountedUcbScheduler::selectOperator(std::mt19937& rng) {
    OperatorFamily fam = selectFamily(rng);
    return selectOperatorWithinFamily(fam, rng);
}

std::string DiscountedUcbScheduler::dumpPolicySnapshot(uint32_t epoch) const {
    nlohmann::json j;
    j["schema_version"] = 1;
    j["epoch"] = epoch;
    j["adaptive_active"] = m_active;
    
    nlohmann::json fams = nlohmann::json::object();
    for (size_t f = 0; f < static_cast<size_t>(OperatorFamily::Count); ++f) {
        fams[toString(static_cast<OperatorFamily>(f))] = {
            {"probability", m_familyProbabilities[f]},
            {"enabled", m_familyEnabled[f]}
        };
    }
    j["family_distribution"] = fams;

    nlohmann::json ops = nlohmann::json::array();
    for (const auto& op : m_operators) {
        ops.push_back({
            {"id", toString(op.id)},
            {"family", toString(op.family)},
            {"enabled", op.enabled},
            {"probability", op.currentProbability},
            {"attempts", op.attempts},
            {"effective_samples", op.effectiveSamples},
            {"discounted_reward", op.discountedReward},
            {"last_reward", op.lastReward},
            {"last_epoch_used", op.lastEpochUsed}
        });
    }
    j["operators"] = ops;
    return j.dump(2);
}

bool DiscountedUcbScheduler::loadPolicySnapshot(const std::string& jsonPath) {
    std::ifstream f(jsonPath);
    if (!f.is_open()) return false;
    try {
        nlohmann::json j;
        f >> j;

        if (j.contains("epoch") && j["epoch"].is_number()) {
            m_currentEpoch = j["epoch"].get<uint32_t>();
        }
        if (j.contains("adaptive_active") && j["adaptive_active"].is_boolean()) {
            m_active = j["adaptive_active"].get<bool>();
        }

        if (j.contains("family_distribution") && j["family_distribution"].is_object()) {
            for (auto& [famName, obj] : j["family_distribution"].items()) {
                OperatorFamily fam = familyFromString(famName);
                size_t fIdx = static_cast<size_t>(fam);
                if (obj.contains("probability")) m_familyProbabilities[fIdx] = obj["probability"].get<double>();
                if (obj.contains("enabled")) m_familyEnabled[fIdx] = obj["enabled"].get<bool>();
            }
        }

        if (j.contains("operators") && j["operators"].is_array()) {
            for (const auto& item : j["operators"]) {
                if (!item.contains("id")) continue;
                OperatorId id = operatorFromString(item["id"].get<std::string>());
                size_t idx = static_cast<size_t>(id);
                auto& op = m_operators[idx];
                if (item.contains("enabled")) op.enabled = item["enabled"].get<bool>();
                if (item.contains("probability")) op.currentProbability = item["probability"].get<double>();
                if (item.contains("attempts")) op.attempts = item["attempts"].get<uint64_t>();
                if (item.contains("effective_samples")) op.effectiveSamples = item["effective_samples"].get<double>();
                if (item.contains("discounted_reward")) op.discountedReward = item["discounted_reward"].get<double>();
                if (item.contains("last_reward")) op.lastReward = item["last_reward"].get<double>();
                if (item.contains("last_epoch_used")) op.lastEpochUsed = item["last_epoch_used"].get<uint32_t>();
            }
        }
        return true;
    } catch (...) {
        return false;
    }
}

} // namespace fastgltf_fuzz

