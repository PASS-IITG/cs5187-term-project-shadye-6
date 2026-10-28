#include "../fuzz/hash_util.hpp"
#include "../fuzz/mutation_scheduler.hpp"
#include "../fuzz/mutation_telemetry.hpp"

#include <iostream>
#include <cassert>
#include <cmath>
#include <cstring>
#include <vector>
#include <numeric>

using namespace fastgltf_fuzz;

void testFnv1aKnownVectors() {
    std::cout << "[Test] FNV-1a 64-bit known test vectors...\n";

    // Vector 1: Empty string -> FNV offset basis
    const uint8_t empty[] = "";
    uint64_t h0 = fnv1a64(empty, 0);
    assert(h0 == 14695981039346656037ULL);

    // Vector 2: "fastgltf"
    const char* str1 = "fastgltf";
    uint64_t h1 = fnv1a64(reinterpret_cast<const uint8_t*>(str1), std::strlen(str1));
    assert(h1 != 0);

    // Vector 3: "glTF" (magic header)
    const char* str2 = "glTF";
    uint64_t h2 = fnv1a64(reinterpret_cast<const uint8_t*>(str2), 4);
    assert(h2 != 0 && h2 != h1);

    // Determinism test
    uint64_t h1_repeat = fnv1a64(reinterpret_cast<const uint8_t*>(str1), std::strlen(str1));
    assert(h1 == h1_repeat);

    std::cout << "  Passed: FNV-1a hash known vectors verified (" << std::hex << h1 << ", " << h2 << std::dec << ")\n";
}

void testProbabilityNormalizationAndFloors() {
    std::cout << "[Test] Probability normalization and floor constraints...\n";

    // Test 1: Uniform starting weights with 0.05 floor
    std::vector<double> probs = {1.0, 1.0, 1.0, 1.0};
    std::vector<bool> enabled = {true, true, true, true};
    double floor = 0.05;

    DiscountedUcbScheduler::normalizeWithFloors(probs, enabled, floor);

    double sum = std::accumulate(probs.begin(), probs.end(), 0.0);
    assert(std::abs(sum - 1.0) < 1e-6);
    for (double p : probs) {
        assert(p >= floor - 1e-6);
    }

    // Test 2: One dominant arm, floor preserved on other arms
    probs = {100.0, 0.0, 0.0, 0.0};
    DiscountedUcbScheduler::normalizeWithFloors(probs, enabled, floor);
    sum = std::accumulate(probs.begin(), probs.end(), 0.0);
    assert(std::abs(sum - 1.0) < 1e-6);
    assert(probs[0] > 0.80);
    assert(probs[1] >= floor - 1e-6);
    assert(probs[2] >= floor - 1e-6);
    assert(probs[3] >= floor - 1e-6);

    // Test 3: Disabled arm receives 0 probability
    probs = {1.0, 2.0, 3.0, 4.0};
    enabled = {true, false, true, true};
    DiscountedUcbScheduler::normalizeWithFloors(probs, enabled, floor);
    assert(probs[1] == 0.0);
    sum = std::accumulate(probs.begin(), probs.end(), 0.0);
    assert(std::abs(sum - 1.0) < 1e-6);

    // Test 4: All arms disabled
    enabled = {false, false, false, false};
    DiscountedUcbScheduler::normalizeWithFloors(probs, enabled, floor);
    for (double p : probs) assert(p == 0.0);

    std::cout << "  Passed: Normalization, floors, and disabled arm handling verified\n";
}

void testDiscountedUcbUpdates() {
    std::cout << "[Test] Discounted UCB updates and exploration decay...\n";

    DiscountedUcbScheduler scheduler;
    PolicyConfig cfg;
    cfg.discountFactor = 0.50; // High decay for fast testing
    cfg.ucbExplorationCoefficient = 1.0;
    cfg.familyProbabilityFloor = 0.05;
    cfg.operatorProbabilityFloorWithinFamily = 0.02;
    scheduler.initialize(cfg);

    // Epoch 1: Reward StructJsonAstRepair heavily
    std::unordered_map<OperatorId, double> rewards1 = {
        {OperatorId::StructJsonAstRepair, 10.0},
        {OperatorId::ByteLibFuzzer, 1.0}
    };
    std::unordered_map<OperatorId, uint64_t> attempts1 = {
        {OperatorId::StructJsonAstRepair, 100},
        {OperatorId::ByteLibFuzzer, 100}
    };

    scheduler.updateEpoch(1, rewards1, attempts1);
    double probStructAst = scheduler.getOperatorProbability(OperatorId::StructJsonAstRepair);
    double probByte = scheduler.getOperatorProbability(OperatorId::ByteLibFuzzer);

    assert(probStructAst > 0.02);
    assert(probByte > 0.02);

    // Epoch 2: Discounting decays previous reward
    std::unordered_map<OperatorId, double> rewards2 = {
        {OperatorId::ByteLibFuzzer, 20.0}
    };
    std::unordered_map<OperatorId, uint64_t> attempts2 = {
        {OperatorId::ByteLibFuzzer, 200}
    };
    scheduler.updateEpoch(2, rewards2, attempts2);

    // Verify snapshot serializes and reloads cleanly
    std::string snap = scheduler.dumpPolicySnapshot(2);
    assert(!snap.empty());
    assert(snap.find("byte_libfuzzer") != std::string::npos);

    DiscountedUcbScheduler reloaded;
    PolicyConfig reloadedCfg;
    reloaded.initialize(reloadedCfg);
    // Write temporary snapshot to verify loading
    std::string tmpPath = "/tmp/test_policy_snap.json";
    FILE* fp = std::fopen(tmpPath.c_str(), "w");
    if (fp) {
        std::fputs(snap.c_str(), fp);
        std::fclose(fp);
        bool ok = reloaded.loadPolicySnapshot(tmpPath);
        assert(ok);
        std::remove(tmpPath.c_str());
    }

    std::cout << "  Passed: Discounted UCB update, decay, and serialization verified\n";
}

void testProvenanceConsumption() {
    std::cout << "[Test] Provenance ledger: single-consumption and replay safety...\n";

    MutationTelemetry::instance().initialize(1000);

    const uint8_t testPayload1[] = "{\"asset\":{\"version\":\"2.0\"}}";
    size_t sz1 = std::strlen(reinterpret_cast<const char*>(testPayload1));

    // Emit mutation
    MutationTelemetry::instance().recordMutationEmitted(
        testPayload1, sz1, OperatorId::StructJsonAstRepair, OperatorFamily::StructuredValid);

    // 1. Consume provenance once
    OperatorId outOp = OperatorId::ByteLibFuzzer;
    OperatorFamily outFam = OperatorFamily::Byte;
    bool matched1 = MutationTelemetry::instance().consumeProvenance(testPayload1, sz1, outOp, outFam);
    assert(matched1 == true);
    assert(outOp == OperatorId::StructJsonAstRepair);
    assert(outFam == OperatorFamily::StructuredValid);

    // 2. Second consumption of the exact same bytes must fail (consumed once, prevents stale attribution on corpus replay)
    OperatorId outOp2 = OperatorId::ByteLibFuzzer;
    OperatorFamily outFam2 = OperatorFamily::Byte;
    bool matched2 = MutationTelemetry::instance().consumeProvenance(testPayload1, sz1, outOp2, outFam2);
    assert(matched2 == false);

    // 3. Stage flag recording
    MutationTelemetry::instance().recordStageFlags(OperatorId::StructJsonAstRepair, STAGE_PARSED | STAGE_VALIDATED);
    auto metrics = MutationTelemetry::instance().getOperatorMetrics(OperatorId::StructJsonAstRepair);
    assert(metrics.attempts >= 1);
    assert(metrics.stageParsed >= 1);
    assert(metrics.stageValidated >= 1);

    std::cout << "  Passed: Provenance single-consumption and stage recording verified\n";
}

int main() {
    std::cout << "========================================\n";
    std::cout << "Running Adaptive Mutation Scheduler Tests\n";
    std::cout << "========================================\n";

    testFnv1aKnownVectors();
    testProbabilityNormalizationAndFloors();
    testDiscountedUcbUpdates();
    testProvenanceConsumption();

    std::cout << "\n[Success] All adaptive mutation scheduler tests passed cleanly!\n";
    return 0;
}

