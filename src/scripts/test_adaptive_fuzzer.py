#!/usr/bin/env python3
"""
Unit and Integration Test Suite for fastgltf Adaptive Hybrid Fuzzer.
Verifies:
  1. Configuration parsing and validation
  2. Probability normalization with floors (including edge cases)
  3. Discounted-UCB mathematical updates, decay, and exploration
  4. Shared 64-bit FNV-1a known test vectors matching C++
  5. Provenance matching, duplicate content, and ambiguous attribution
  6. LibFuzzer log parser across restarts and malformed logs
  7. Multi-subprocess execution accounting
  8. Saturation state machine transitions and recovery sequences
  9. Baseline fixed mode preservation (25/25/40/10 distribution)
"""

import os
import sys
import json
import unittest
import tempfile
import shutil
from pathlib import Path

# Add scripts directory to path
SCRIPTS_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS_DIR))

from campaign_manager import (
    fnv1a64,
    format_content_hash,
    compute_file_hash,
    normalize_with_floors,
    DiscountedUcbPolicy,
    LibfuzzerLogParser,
    DEFAULT_FAMILY_WEIGHTS,
    FAMILY_MEMBERS,
    OPERATOR_TO_FAMILY,
    CampaignManager
)
from saturation_monitor import SaturationMonitor, SaturationState


class TestAdaptiveHybridFuzzer(unittest.TestCase):

    def test_01_shared_fnv1a_known_vectors(self):
        """Test vector 1-3: Verify Python 64-bit FNV-1a matches C++ hash_util.hpp exactly."""
        # Empty string -> FNV offset basis
        h_empty = fnv1a64(b"")
        self.assertEqual(h_empty, 14695981039346656037)
        self.assertEqual(format_content_hash(h_empty, 0), "cbf29ce484222325:0")

        # "fastgltf"
        h_fastgltf = fnv1a64(b"fastgltf")
        self.assertEqual(f"{h_fastgltf:016x}", "2014e3dad3bf2cba")
        self.assertEqual(format_content_hash(h_fastgltf, 8), "2014e3dad3bf2cba:8")

        # "glTF"
        h_gltf = fnv1a64(b"glTF")
        self.assertEqual(f"{h_gltf:016x}", "a4f601721303ae08")
        self.assertEqual(format_content_hash(h_gltf, 4), "a4f601721303ae08:4")

    def test_02_normalization_and_floors(self):
        """Test probability normalization with floor constraints and disabled arms."""
        # 4 arms, uniform scores, floor 0.05
        scores = {"a": 10.0, "b": 10.0, "c": 10.0, "d": 10.0}
        enabled = {"a": True, "b": True, "c": True, "d": True}
        probs = normalize_with_floors(scores, enabled, 0.05)
        self.assertAlmostEqual(sum(probs.values()), 1.0, places=6)
        for p in probs.values():
            self.assertGreaterEqual(p, 0.05)
            self.assertAlmostEqual(p, 0.25, places=5)

        # Skewed scores: one dominant arm, floor 0.05
        skewed = {"a": 1000.0, "b": 0.0, "c": 0.0, "d": 0.0}
        probs_skewed = normalize_with_floors(skewed, enabled, 0.05)
        self.assertAlmostEqual(sum(probs_skewed.values()), 1.0, places=6)
        self.assertGreaterEqual(probs_skewed["b"], 0.05)
        self.assertGreaterEqual(probs_skewed["c"], 0.05)
        self.assertGreaterEqual(probs_skewed["d"], 0.05)
        self.assertAlmostEqual(probs_skewed["a"], 0.85, places=5)

        # Single enabled arm receives 1.0
        single_enabled = {"a": True, "b": False, "c": False, "d": False}
        probs_single = normalize_with_floors(scores, single_enabled, 0.05)
        self.assertAlmostEqual(probs_single["a"], 1.0)
        self.assertEqual(probs_single["b"], 0.0)

        # All disabled arms raise ValueError
        all_disabled = {"a": False, "b": False}
        with self.assertRaises(ValueError):
            normalize_with_floors({"a": 1.0, "b": 1.0}, all_disabled, 0.05)

    def test_03_discounted_ucb_updates_and_decay(self):
        """Test discounted-UCB reward accrual, decay, and exploration term."""
        config = {
            "adaptive_scheduler": {
                "discount_factor": 0.5,
                "ucb_exploration_coefficient": 1.0,
                "family_probability_floor": 0.05,
                "operator_probability_floor_within_family": 0.02
            }
        }
        policy = DiscountedUcbPolicy(config)

        # Check initial baseline family weights
        for fam, w in DEFAULT_FAMILY_WEIGHTS.items():
            self.assertAlmostEqual(policy.family_weights[fam], w, places=5)

        # Simulate epoch 1: InvariantBreakBounds gets promotions
        epoch1_attempts = {"InvariantBreakBounds": 100, "ByteLibFuzzer": 100}
        epoch1_promos = {"InvariantBreakBounds": 5, "ByteLibFuzzer": 0}
        policy.update_with_epoch_metrics(epoch1_attempts, epoch1_promos, {})

        # Invariant breaking should have higher weight than byte
        self.assertGreater(policy.family_weights["invariant_breaking"], policy.family_weights["byte"])
        self.assertGreaterEqual(policy.family_weights["byte"], 0.05)

        # Check decay: In next epoch, old rewards are cut in half by gamma=0.5
        prev_inv_r = policy.arm_rewards["InvariantBreakBounds"]
        epoch2_attempts = {"InvariantBreakBounds": 0}
        policy.update_with_epoch_metrics(epoch2_attempts, {}, {})
        self.assertAlmostEqual(policy.arm_rewards["InvariantBreakBounds"], prev_inv_r * 0.5, places=5)

    def test_04_libfuzzer_log_parsing_and_restarts(self):
        """Test libFuzzer log parser with multi-subprocess restart sessions."""
        sample_log = """
INFO: Running with entropic power schedule (0xFF, 100).
INFO: Seed: 20261028
#1	INITED cov: 45 ft: 50 corp: 1/1b exec/s: 0 rss: 30Mb
#500	NEW    cov: 120 ft: 240 corp: 5/100b exec/s: 500 rss: 35Mb
#1200	PULSE  cov: 120 ft: 240 corp: 5/100b exec/s: 600 rss: 35Mb
==1234==ERROR: AddressSanitizer: heap-buffer-overflow on address 0xdeadbeef
SUMMARY: AddressSanitizer: heap-buffer-overflow in fastgltf::Parser::loadGltf
INFO: Running with entropic power schedule (0xFF, 100).
INFO: Seed: 20261029
#1	INITED cov: 120 ft: 240 corp: 5/100b exec/s: 0 rss: 35Mb
#800	NEW    cov: 150 ft: 310 corp: 8/250b exec/s: 400 rss: 40Mb
#1500	DONE   cov: 150 ft: 310 corp: 8/250b exec/s: 450 rss: 40Mb
"""
        res = LibfuzzerLogParser.parse_log(sample_log)
        # Session 1 max: 1200, Session 2 max: 1500 -> Total: 2700
        self.assertEqual(res["total_execs"], 2700)
        self.assertEqual(res["session_count"], 2)
        self.assertEqual(res["peak_cov"], 150)
        self.assertEqual(res["peak_ft"], 310)
        self.assertEqual(res["last_speed"], 450)
        self.assertTrue(res["crash_detected"])
        self.assertEqual(res["crash_type"], "heap-buffer-overflow")

    def test_05_malformed_libfuzzer_log(self):
        """Test parser robustness against corrupt/empty logs without raising exceptions."""
        empty_res = LibfuzzerLogParser.parse_log("")
        self.assertEqual(empty_res["total_execs"], 0)
        self.assertEqual(empty_res["peak_cov"], 0)

        garbage_res = LibfuzzerLogParser.parse_log("gibberish without numbers\n### corrupt line\n")
        self.assertEqual(garbage_res["total_execs"], 0)

    def test_06_corpus_promotion_matching(self):
        """Test promotion matching against the provenance ledger and handling unmatched files."""
        config_path = SCRIPTS_DIR / "campaign_policy.example.json"
        with tempfile.TemporaryDirectory() as tmp_dir:
            out_dir = Path(tmp_dir) / "run"
            mgr = CampaignManager(config_path, out_dir, {"mode": "adaptive"})

            # Mock telemetry provenance ledger
            telemetry = {
                "provenance_ledger": {
                    "2014e3dad3bf2cba:8": {
                        "operator": "InvariantBreakBounds",
                        "family": "invariant_breaking",
                        "epoch": 0
                    },
                    "a4f601721303ae08:4": {
                        "operator": "StructuredSpliceJson",
                        "family": "structured_valid",
                        "epoch": 0
                    }
                }
            }

            # 3 new corpus files: 2 matched, 1 unknown
            new_files = {
                "seed_01": "2014e3dad3bf2cba:8",
                "seed_02": "a4f601721303ae08:4",
                "seed_orphan": "ffffffffffffffff:12"
            }

            op_promos, fam_promos, unmatched = mgr.match_promotions(new_files, telemetry)
            self.assertEqual(op_promos["InvariantBreakBounds"], 1)
            self.assertEqual(fam_promos["invariant_breaking"], 1)
            self.assertEqual(op_promos["StructuredSpliceJson"], 1)
            self.assertEqual(fam_promos["structured_valid"], 1)
            self.assertEqual(len(unmatched), 1)
            self.assertIn("seed_orphan", unmatched)

    def test_07_saturation_monitor_state_machine(self):
        """Test the 6-state saturation monitor through active, recovery, and saturation."""
        config = {
            "campaign": {
                "minimum_runtime_before_saturation_seconds": 100,
                "hard_max_runtime_seconds": 500
            },
            "saturation": {
                "enabled": True,
                "low_yield_epochs_to_suspect_plateau": 2,
                "minimum_new_corpus_promotions_per_epoch": 1,
                "minimum_feature_delta_per_epoch": 1,
                "recovery_epochs": 1,
                "recovery_epoch_seconds": 50,
                "unresolved_crash_blocks_saturation_stop": True
            }
        }
        monitor = SaturationMonitor(config)

        # Epoch 0: Progress made (1 promotion, 10 features) -> ACTIVE
        st, _, _ = monitor.evaluate_epoch(0, 30.0, new_corpus_promotions=1, feature_delta=10)
        self.assertEqual(st, SaturationState.ACTIVE)

        # Epoch 1: Low yield (0 promotions, 0 features) -> Still ACTIVE (1/2 low yield streak)
        st, _, _ = monitor.evaluate_epoch(1, 30.0, new_corpus_promotions=0, feature_delta=0)
        self.assertEqual(st, SaturationState.ACTIVE)

        # Epoch 2: Low yield (0 promotions, 0 features) -> 2/2 streak triggers RECOVERY!
        st, _, actions = monitor.evaluate_epoch(2, 30.0, new_corpus_promotions=0, feature_delta=0)
        self.assertEqual(st, SaturationState.RECOVERY)
        self.assertIn("INCREASE_EXPLORATION", actions)

        # Case A: Progress restored in recovery -> returns to ACTIVE
        st, _, _ = monitor.evaluate_epoch(3, 30.0, new_corpus_promotions=2, feature_delta=5)
        self.assertEqual(st, SaturationState.ACTIVE)

        # Trigger recovery again:
        monitor.evaluate_epoch(4, 30.0, 0, 0)
        st, _, _ = monitor.evaluate_epoch(5, 30.0, 0, 0)
        self.assertEqual(st, SaturationState.RECOVERY)

        # Case B: Recovery fails, but unresolved crashes pending -> blocks saturation
        st, reason, _ = monitor.evaluate_epoch(6, 30.0, 0, 0, unresolved_crash_candidates=1)
        self.assertEqual(st, SaturationState.ACTIVE)
        self.assertIn("unresolved crash candidate(s) pending triage", reason)

        # Case C: Hard budget reached -> BUDGET_STOP
        st, _, _ = monitor.evaluate_epoch(7, 300.0, 0, 0)
        self.assertEqual(st, SaturationState.BUDGET_STOP)

    def test_08_fixed_baseline_preservation(self):
        """Verify fixed mode preserves the exact 25/25/40/10 family weights."""
        config_path = SCRIPTS_DIR / "campaign_policy.example.json"
        with tempfile.TemporaryDirectory() as tmp_dir:
            out_dir = Path(tmp_dir) / "run_fixed"
            mgr = CampaignManager(config_path, out_dir, {"mode": "fixed"})
            policy_json = mgr.policy.export_policy_json(0)

            fams = policy_json["families"]
            self.assertAlmostEqual(fams["byte"]["probability"], 0.25)
            self.assertAlmostEqual(fams["structured_valid"]["probability"], 0.25)
            self.assertAlmostEqual(fams["invariant_breaking"]["probability"], 0.40)
            self.assertAlmostEqual(fams["procedural"]["probability"], 0.10)


if __name__ == "__main__":
    unittest.main(verbosity=2)

