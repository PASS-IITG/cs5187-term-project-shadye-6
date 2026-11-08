#!/usr/bin/env python3
"""
Adaptive Hybrid Fuzzing Campaign Manager for fastgltf.
Orchestrates epoch-based fuzzing, discounted-UCB mutation adaptation,
conservative saturation monitoring, restart-resilient execution accounting,
and unambiguous corpus promotion matching.

Modes supported:
  - fixed: Constant 25/25/40/10 baseline family distribution.
  - adaptive: Discounted-UCB dynamic scheduler updating weights per epoch.
  - fixed_with_saturation: Fixed distribution + conservative saturation monitor.
  - adaptive_with_saturation: Both adaptive scheduler and saturation monitor active.
"""

import os
import sys
import json
import time
import shutil
import signal
import subprocess
import argparse
import math
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple, Set

# Shared 64-bit FNV-1a content hash specification with C++ hash_util.hpp
FNV_OFFSET_BASIS = 14695981039346656037
FNV_PRIME = 1099511628211
MASK_64 = 0xFFFFFFFFFFFFFFFF


def fnv1a64(data: bytes) -> int:
    """Computes 64-bit FNV-1a non-cryptographic content hash."""
    h = FNV_OFFSET_BASIS
    for b in data:
        h = (h ^ b) & MASK_64
        h = (h * FNV_PRIME) & MASK_64
    return h


def format_content_hash(hash_val: int, size: int) -> str:
    """Formats 64-bit hash and payload size as hex:size matching formatContentHash in C++."""
    return f"{hash_val:016x}:{size}"


def compute_file_hash(path: Path) -> Tuple[str, int]:
    """Reads a file and returns (format_content_hash, byte_size)."""
    data = path.read_bytes()
    h = fnv1a64(data)
    return format_content_hash(h, len(data)), len(data)


OPERATOR_TO_FAMILY = {
    "ByteLibFuzzer": "byte",
    "ByteBitFlip": "byte",
    "ByteRandomReplace": "byte",
    "ByteInsertDelete": "byte",
    "StructuredSpliceJson": "structured_valid",
    "StructuredPerturbNumbers": "structured_valid",
    "StructuredShuffleKeys": "structured_valid",
    "StructuredMutateStrings": "structured_valid",
    "InvariantBreakBounds": "invariant_breaking",
    "InvariantBreakOffsets": "invariant_breaking",
    "InvariantCorruptTypes": "invariant_breaking",
    "InvariantCyclicNodes": "invariant_breaking",
    "ProceduralValidGltf": "procedural",
    "ProceduralValidGlb": "procedural",
    "ProceduralCorruptedGltf": "procedural",
    "ProceduralCorruptedGlb": "procedural",
}

FAMILY_MEMBERS = {
    "byte": ["ByteLibFuzzer", "ByteBitFlip", "ByteRandomReplace", "ByteInsertDelete"],
    "structured_valid": ["StructuredSpliceJson", "StructuredPerturbNumbers", "StructuredShuffleKeys", "StructuredMutateStrings"],
    "invariant_breaking": ["InvariantBreakBounds", "InvariantBreakOffsets", "InvariantCorruptTypes", "InvariantCyclicNodes"],
    "procedural": ["ProceduralValidGltf", "ProceduralValidGlb", "ProceduralCorruptedGltf", "ProceduralCorruptedGlb"],
}

DEFAULT_FAMILY_WEIGHTS = {
    "byte": 0.25,
    "structured_valid": 0.25,
    "invariant_breaking": 0.40,
    "procedural": 0.10,
}


def normalize_with_floors(scores: Dict[str, float],
                         enabled: Dict[str, bool],
                         floor: float) -> Dict[str, float]:
    """
    Normalizes scores into probabilities such that every enabled arm receives at least floor.
    Disabled arms receive 0.0.
    """
    enabled_keys = [k for k, en in enabled.items() if en]
    if not enabled_keys:
        raise ValueError("Cannot normalize: all arms are disabled")

    num_enabled = len(enabled_keys)
    if floor * num_enabled > 1.0 + 1e-9:
        floor = 1.0 / num_enabled

    # Ensure non-negative scores
    non_neg_scores = {k: max(0.0, scores.get(k, 0.0)) for k in enabled_keys}
    total_score = sum(non_neg_scores.values())

    remaining_prob = 1.0 - (floor * num_enabled)
    result = {k: 0.0 for k in enabled.keys()}

    if total_score <= 1e-9:
        uniform = 1.0 / num_enabled
        for k in enabled_keys:
            result[k] = uniform
    else:
        for k in enabled_keys:
            result[k] = floor + remaining_prob * (non_neg_scores[k] / total_score)

    return result


class LibfuzzerLogParser:
    """
    Parses libFuzzer execution logs, aggregating metrics across child sessions.
    Handles restarts, signals, and malformed lines gracefully.
    """

    @staticmethod
    def parse_log(log_text: str) -> Dict[str, Any]:
        sessions_max_execs: List[int] = []
        current_session_exec = 0
        peak_cov = 0
        peak_ft = 0
        last_speed = 0
        crash_detected = False
        crash_type = None

        for line in log_text.splitlines():
            line_str = line.strip()

            # Session delimiter markers
            if "INFO: Running with entropic" in line_str or "Dictionary: " in line_str:
                if current_session_exec > 0:
                    sessions_max_execs.append(current_session_exec)
                    current_session_exec = 0
                continue

            # Check for crash markers
            if "ERROR: AddressSanitizer:" in line_str or "runtime error:" in line_str:
                crash_detected = True
                if "heap-buffer-overflow" in line_str:
                    crash_type = "heap-buffer-overflow"
                elif "global-buffer-overflow" in line_str:
                    crash_type = "global-buffer-overflow"
                elif "stack-overflow" in line_str:
                    crash_type = "stack-overflow"
                elif crash_type is None:
                    crash_type = line_str

            # Parse exec count & exec/s: #12345 ... exec/s: 567
            if line_str.startswith("#"):
                parts = line_str.split()
                if len(parts) >= 2:
                    num_str = parts[0][1:]
                    if num_str.isdigit():
                        val = int(num_str)
                        if val > current_session_exec:
                            current_session_exec = val

                if "cov:" in line_str and "ft:" in line_str:
                    try:
                        cov_part = line_str.split("cov:")[1].split()[0]
                        ft_part = line_str.split("ft:")[1].split()[0]
                        if cov_part.isdigit() and int(cov_part) > peak_cov:
                            peak_cov = int(cov_part)
                        if ft_part.isdigit() and int(ft_part) > peak_ft:
                            peak_ft = int(ft_part)
                    except (IndexError, ValueError):
                        pass

                if "exec/s:" in line_str:
                    try:
                        spd_part = line_str.split("exec/s:")[1].split()[0]
                        if spd_part.isdigit():
                            last_speed = int(spd_part)
                    except (IndexError, ValueError):
                        pass

        if current_session_exec > 0:
            sessions_max_execs.append(current_session_exec)

        total_execs = sum(sessions_max_execs)
        num_sessions = max(1, len(sessions_max_execs))

        return {
            "total_execs": total_execs,
            "session_execs": sessions_max_execs,
            "session_count": num_sessions,
            "peak_cov": peak_cov,
            "peak_ft": peak_ft,
            "last_speed": last_speed,
            "crash_detected": crash_detected,
            "crash_type": crash_type,
        }


class DiscountedUcbPolicy:
    """
    Python implementation of Discounted-UCB policy updater.
    Calculates next family and sub-operator weights at epoch boundaries.
    """

    def __init__(self, config: Dict[str, Any]):
        sched_cfg = config.get("adaptive_scheduler", {})
        self.discount_factor: float = sched_cfg.get("discount_factor", 0.90)
        self.ucb_coeff: float = sched_cfg.get("ucb_exploration_coefficient", 0.75)
        self.family_floor: float = sched_cfg.get("family_probability_floor", 0.05)
        self.op_floor: float = sched_cfg.get("operator_probability_floor_within_family", 0.02)
        self.reward_weights: Dict[str, float] = sched_cfg.get("reward_weights", {
            "corpus_promotion": 1.0,
            "novel_stage_outcome": 0.5,
            "novel_oracle_candidate": 2.0,
            "novel_crash_candidate": 1.0
        })
        self.max_single_reward: float = sched_cfg.get("max_single_event_reward", 1.0)

        # Initialize arm statistics
        self.arm_attempts: Dict[str, float] = {op: 0.0 for op in OPERATOR_TO_FAMILY.keys()}
        self.arm_rewards: Dict[str, float] = {op: 0.0 for op in OPERATOR_TO_FAMILY.keys()}
        self.family_attempts: Dict[str, float] = {fam: 0.0 for fam in FAMILY_MEMBERS.keys()}
        self.family_rewards: Dict[str, float] = {fam: 0.0 for fam in FAMILY_MEMBERS.keys()}

        # Current weights
        self.family_weights: Dict[str, float] = dict(sched_cfg.get("initial_family_weights", DEFAULT_FAMILY_WEIGHTS))
        self.operator_weights: Dict[str, float] = {}
        for fam, members in FAMILY_MEMBERS.items():
            prob = 1.0 / len(members)
            for m in members:
                self.operator_weights[m] = prob

    def update_with_epoch_metrics(self,
                                  operator_attempts_epoch: Dict[str, int],
                                  operator_promotions_epoch: Dict[str, int],
                                  operator_stages_epoch: Dict[str, int],
                                  exploration_boost: float = 1.0) -> None:
        """Applies discounted UCB updates and recalculates weights."""
        gamma = self.discount_factor
        c = self.ucb_coeff * exploration_boost

        # 1. Decay historical attempts and rewards
        for op in OPERATOR_TO_FAMILY.keys():
            self.arm_attempts[op] *= gamma
            self.arm_rewards[op] *= gamma

        for fam in FAMILY_MEMBERS.keys():
            self.family_attempts[fam] *= gamma
            self.family_rewards[fam] *= gamma

        # 2. Add current epoch observations
        for op, attempts in operator_attempts_epoch.items():
            if attempts <= 0:
                continue
            promos = operator_promotions_epoch.get(op, 0)
            stages = operator_stages_epoch.get(op, 0)

            # Configured bounded reward model
            raw_reward = (self.reward_weights.get("corpus_promotion", 1.0) * promos +
                          self.reward_weights.get("novel_stage_outcome", 0.5) * stages)
            # Log1p scaling to prevent prolific operators from dominating
            bounded_reward = math.log1p(raw_reward)
            bounded_reward = min(bounded_reward, self.max_single_reward * max(1, attempts))

            self.arm_attempts[op] += attempts
            self.arm_rewards[op] += bounded_reward

            fam = OPERATOR_TO_FAMILY[op]
            self.family_attempts[fam] += attempts
            self.family_rewards[fam] += bounded_reward

        # 3. Calculate Family UCB Scores
        total_fam_attempts = sum(self.family_attempts.values())
        fam_scores = {}
        for fam in FAMILY_MEMBERS.keys():
            n = self.family_attempts[fam]
            r = self.family_rewards[fam]
            if n < 1.0 or total_fam_attempts < 1.0:
                fam_scores[fam] = 1.0  # High bonus for unexercised families
            else:
                mean = r / n
                explore = c * math.sqrt(math.log(max(1.0, total_fam_attempts)) / n)
                fam_scores[fam] = mean + explore

        fam_enabled = {f: True for f in FAMILY_MEMBERS.keys()}
        self.family_weights = normalize_with_floors(fam_scores, fam_enabled, self.family_floor)

        # 4. Calculate Sub-Operator UCB Scores within each family
        for fam, members in FAMILY_MEMBERS.items():
            total_member_attempts = sum(self.arm_attempts[m] for m in members)
            op_scores = {}
            for m in members:
                n = self.arm_attempts[m]
                r = self.arm_rewards[m]
                if n < 1.0 or total_member_attempts < 1.0:
                    op_scores[m] = 1.0
                else:
                    mean = r / n
                    explore = c * math.sqrt(math.log(max(1.0, total_member_attempts)) / n)
                    op_scores[m] = mean + explore

            op_enabled = {m: True for m in members}
            norm_ops = normalize_with_floors(op_scores, op_enabled, self.op_floor)
            for m, w in norm_ops.items():
                self.operator_weights[m] = w

    def export_policy_json(self, epoch_id: int) -> Dict[str, Any]:
        """Generates policy dictionary ready for serialization to disk."""
        operators_list = []
        for op, fam in OPERATOR_TO_FAMILY.items():
            prob = self.operator_weights.get(op, 0.25)
            operators_list.append({
                "name": op,
                "family": fam,
                "enabled": True,
                "probability": prob,
                "floor": self.op_floor,
                "n_attempts": self.arm_attempts.get(op, 0.0),
                "r_discounted": self.arm_rewards.get(op, 0.0)
            })

        families_dict = {}
        for fam in FAMILY_MEMBERS.keys():
            families_dict[fam] = {
                "probability": self.family_weights.get(fam, 0.25),
                "floor": self.family_floor,
                "n_attempts": self.family_attempts.get(fam, 0.0),
                "r_discounted": self.family_rewards.get(fam, 0.0)
            }

        return {
            "schema_version": 1,
            "epoch_id": epoch_id,
            "algorithm": "discounted_ucb",
            "discount_factor": self.discount_factor,
            "ucb_exploration_coefficient": self.ucb_coeff,
            "families": families_dict,
            "operators": operators_list
        }


class CampaignManager:
    """
    Supervises full fuzzing campaign over epochs, coordinating subprocesses,
    collecting telemetry, matching promotions, updating policy, and querying saturation.
    """

    def __init__(self, config_path: Path, output_dir: Path, cli_overrides: Dict[str, Any]):
        self.output_dir = output_dir.resolve()
        self.output_dir.mkdir(parents=True, exist_ok=True)

        # Load and validate config
        if not config_path.is_file():
            raise FileNotFoundError(f"Configuration file not found: {config_path}")
        with open(config_path, "r", encoding="utf-8") as f:
            self.config = json.load(f)

        # Apply CLI overrides
        for k, v in cli_overrides.items():
            if v is not None:
                if k in ("mode", "seed"):
                    self.config[k] = v
                elif k in ("epoch_seconds", "hard_max_runtime_seconds", "target", "build"):
                    self.config.setdefault("campaign", {})[k] = v

        self.mode = self.config.get("mode", "adaptive_with_saturation")
        if self.mode not in ("fixed", "adaptive", "fixed_with_saturation", "adaptive_with_saturation"):
            raise ValueError(f"Unknown campaign mode: '{self.mode}'. Must be one of: fixed, adaptive, fixed_with_saturation, adaptive_with_saturation")

        camp_cfg = self.config.setdefault("campaign", {})
        self.epoch_seconds = camp_cfg.get("epoch_seconds", 300)
        self.hard_max_runtime_seconds = camp_cfg.get("hard_max_runtime_seconds", 7200)
        self.seed = self.config.get("seed", 20261028)
        self.target = camp_cfg.get("target", "deep_fuzzer")
        self.build_type = camp_cfg.get("build", "asan")

        # Directories
        self.corpus_dir = self.output_dir / "corpus"
        self.crashes_dir = self.output_dir / "findings" / "crashes"
        self.corpus_dir.mkdir(parents=True, exist_ok=True)
        self.crashes_dir.mkdir(parents=True, exist_ok=True)

        # Initialize Saturation Monitor
        from saturation_monitor import SaturationMonitor, SaturationState
        self.saturation_monitor = SaturationMonitor(self.config)
        self.SaturationState = SaturationState

        # Initialize Policy
        self.policy = DiscountedUcbPolicy(self.config)

        # Tracking state
        self.current_epoch = 0
        self.total_elapsed_time = 0.0
        self.total_executions = 0
        self.total_restarts = 0
        self.corpus_history: List[Dict[str, str]] = []
        self.epoch_metrics_history: List[Dict[str, Any]] = []
        self.initial_corpus_manifest: Dict[str, str] = {}
        self.current_corpus_manifest: Dict[str, str] = {}
        self.known_crashes: Set[str] = set()

    def initialize_corpus(self, seed_corpus_path: Optional[Path]) -> None:
        """Initializes working corpus from seed directory if empty."""
        existing_files = list(self.corpus_dir.glob("*"))
        if not existing_files and seed_corpus_path and seed_corpus_path.is_dir():
            print(f"[*] Seeding working corpus from {seed_corpus_path}...")
            for f in seed_corpus_path.glob("*"):
                if f.is_file() and not f.name.startswith("."):
                    shutil.copy2(f, self.corpus_dir / f.name)

        # Snapshot initial corpus
        for f in self.corpus_dir.glob("*"):
            if f.is_file():
                h_str, _ = compute_file_hash(f)
                self.initial_corpus_manifest[f.name] = h_str
        self.current_corpus_manifest = dict(self.initial_corpus_manifest)
        print(f"[*] Initial corpus contains {len(self.current_corpus_manifest)} seeds.")

    def run_epoch_subprocess(self, epoch_id: int, epoch_dir: Path, duration_sec: int) -> Tuple[int, int, Dict[str, Any], str]:
        """
        Runs libFuzzer target in an epoch with restart supervision.
        Accumulates executions across ALL child processes.
        """
        bin_path = Path(__file__).resolve().parent.parent / f"build-{self.build_type}" / self.target
        if not bin_path.is_file():
            raise FileNotFoundError(f"Target binary not found: {bin_path}. Run build.sh {self.build_type} first.")

        epoch_log_file = epoch_dir / f"epoch_{epoch_id:03d}.log"
        telemetry_file = epoch_dir / f"epoch_{epoch_id:03d}_telemetry.json"
        policy_file = epoch_dir / f"policy_epoch_{epoch_id:03d}.json"

        # Determine fuzz mode for binary environment
        fuzz_mode = "hybrid"
        if self.mode == "fixed":
            fuzz_mode = "hybrid"

        env = os.environ.copy()
        env["FUZZ_MODE"] = fuzz_mode
        env["ASAN_OPTIONS"] = "abort_on_error=1:detect_leaks=0:symbolize=1"
        env["UBSAN_OPTIONS"] = "print_stacktrace=1:halt_on_error=1:abort_on_error=1:symbolize=1"

        if self.mode in ("adaptive", "adaptive_with_saturation"):
            env["ADAPTIVE_POLICY_PATH"] = str(policy_file)
            env["MUTATION_TELEMETRY_PATH"] = str(telemetry_file)
            env["MUTATION_TELEMETRY_INTERVAL"] = "4096"

        epoch_start_time = time.time()
        epoch_end_time = epoch_start_time + duration_sec
        epoch_executions = 0
        restarts = 0
        all_logs: List[str] = []

        dict_file = Path(__file__).resolve().parent.parent / "corpus" / "gltf.dict"

        while True:
            now = time.time()
            remaining_time = int(epoch_end_time - now)
            if remaining_time <= 0:
                break

            cmd = [
                str(bin_path),
                str(self.corpus_dir),
                f"-max_total_time={remaining_time}",
                "-timeout=10",
                f"-seed={self.seed + epoch_id * 100 + restarts}",
                f"-artifact_prefix={self.crashes_dir}/",
                "-len_control=0",
                "-max_len=65536"
            ]
            if dict_file.is_file() and self.target in ("deep_fuzzer", "parser_fuzzer"):
                cmd.append(f"-dict={dict_file}")

            proc = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                env=env,
                errors="replace"
            )

            all_logs.append(proc.stdout)
            sub_res = LibfuzzerLogParser.parse_log(proc.stdout)
            epoch_executions += sub_res["total_execs"]

            if proc.returncode != 0:
                restarts += 1
                # Small pause to yield CPU on immediate crash loops
                time.sleep(0.1)
            else:
                # Normal clean exit upon reaching max_total_time
                break

        full_log_str = "\n".join(all_logs)
        with open(epoch_log_file, "w", encoding="utf-8") as f:
            f.write(full_log_str)

        final_parsed = LibfuzzerLogParser.parse_log(full_log_str)
        final_parsed["total_execs"] = epoch_executions

        actual_elapsed = time.time() - epoch_start_time
        return epoch_executions, restarts, final_parsed, str(telemetry_file)

    def match_promotions(self,
                         new_corpus_files: Dict[str, str],
                         telemetry_data: Dict[str, Any]) -> Tuple[Dict[str, int], Dict[str, int], List[str]]:
        """
        Matches newly retained corpus files against the provenance ledger.
        Returns (operator_promotions, family_promotions, unmatched_files).
        """
        ledger = telemetry_data.get("provenance_ledger", {})
        operator_promotions: Dict[str, int] = {op: 0 for op in OPERATOR_TO_FAMILY.keys()}
        family_promotions: Dict[str, int] = {fam: 0 for fam in FAMILY_MEMBERS.keys()}
        unmatched_files: List[str] = []

        for fname, hash_size_key in new_corpus_files.items():
            if hash_size_key in ledger:
                entry = ledger[hash_size_key]
                op = entry.get("operator")
                fam = entry.get("family")
                if op in operator_promotions:
                    operator_promotions[op] += 1
                if fam in family_promotions:
                    family_promotions[fam] += 1
            else:
                unmatched_files.append(fname)

        return operator_promotions, family_promotions, unmatched_files

    def run_campaign(self, max_epochs: int = 100) -> Dict[str, Any]:
        """Executes the full campaign until saturation, budget stop, or max epochs."""
        print("==========================================================")
        print(" Fastgltf Fuzzing Campaign Manager")
        print(f" Mode          : {self.mode}")
        print(f" Target        : {self.target} ({self.build_type})")
        print(f" Output Dir    : {self.output_dir}")
        print(f" Epoch Budget  : {self.epoch_seconds}s")
        print(f" Hard Budget   : {self.hard_max_runtime_seconds}s")
        print("==========================================================")

        # Write config_used.json
        with open(self.output_dir / "config_used.json", "w", encoding="utf-8") as f:
            json.dump(self.config, f, indent=2)

        stopping_reason = "MAX_EPOCHS_REACHED"
        final_saturation_state = "ACTIVE"
        prev_peak_ft = 0

        while self.current_epoch < max_epochs:
            epoch_id = self.current_epoch
            epoch_dir = self.output_dir
            print(f"\n[+] Starting Epoch {epoch_id:03d} (Elapsed: {self.total_elapsed_time:.1f}s / {self.hard_max_runtime_seconds}s)")

            # 1. Snapshot and serialize policy for this epoch
            policy_json = self.policy.export_policy_json(epoch_id)
            policy_file = epoch_dir / f"policy_epoch_{epoch_id:03d}.json"
            with open(policy_file, "w", encoding="utf-8") as f:
                json.dump(policy_json, f, indent=2)

            # 2. Run libFuzzer subprocess(es) for epoch
            execs, restarts, log_metrics, telem_path = self.run_epoch_subprocess(
                epoch_id, epoch_dir, self.epoch_seconds
            )
            self.total_executions += execs
            self.total_restarts += restarts
            self.total_elapsed_time += self.epoch_seconds

            # 3. Snapshot new corpus additions
            new_corpus_files: Dict[str, str] = {}
            for f in self.corpus_dir.glob("*"):
                if f.is_file() and f.name not in self.current_corpus_manifest:
                    h_str, _ = compute_file_hash(f)
                    new_corpus_files[f.name] = h_str
                    self.current_corpus_manifest[f.name] = h_str

            new_promotions_count = len(new_corpus_files)
            print(f"  [Epoch {epoch_id:03d}] Executions: {execs:,} | Restarts: {restarts} | New Corpus Seeds: {new_promotions_count}")

            # 4. Load Telemetry Snapshot if available
            telemetry_data = {}
            telemetry_valid = False
            if os.path.isfile(telem_path):
                try:
                    with open(telem_path, "r", encoding="utf-8") as f:
                        telemetry_data = json.load(f)
                    telemetry_valid = True
                except Exception as e:
                    print(f"  [Warning] Failed to parse telemetry snapshot: {e}")

            # 5. Match Promotions
            op_promos, fam_promos, unmatched = self.match_promotions(new_corpus_files, telemetry_data)
            attribution_cov = 1.0
            if new_promotions_count > 0:
                attribution_cov = (new_promotions_count - len(unmatched)) / float(new_promotions_count)

            # 6. Compute Feature & Stage Deltas
            current_peak_ft = log_metrics.get("peak_ft", 0)
            feature_delta = max(0, current_peak_ft - prev_peak_ft)
            prev_peak_ft = max(prev_peak_ft, current_peak_ft)

            # Compute Stage metrics from telemetry
            op_attempts_epoch: Dict[str, int] = {}
            op_stages_epoch: Dict[str, int] = {}
            total_stages = 0
            if telemetry_valid and "operators" in telemetry_data:
                for op_name, m in telemetry_data["operators"].items():
                    op_attempts_epoch[op_name] = m.get("attempts", 0)
                    stages_hit = (m.get("stage_validated", 0) +
                                  m.get("stage_mesh_indices", 0) +
                                  m.get("stage_accessor_exercised", 0) +
                                  m.get("stage_oracle_triggered", 0))
                    op_stages_epoch[op_name] = stages_hit
                    total_stages += stages_hit

            # 7. Check for crashes
            crash_candidates = list(self.crashes_dir.glob("crash-*"))
            new_crashes = [c for c in crash_candidates if c.name not in self.known_crashes]
            for c in new_crashes:
                self.known_crashes.add(c.name)

            # 8. Record Epoch Metrics
            epoch_metrics = {
                "epoch": epoch_id,
                "duration_seconds": self.epoch_seconds,
                "total_elapsed_seconds": self.total_elapsed_time,
                "executions": execs,
                "total_campaign_executions": self.total_executions,
                "restarts": restarts,
                "peak_coverage": log_metrics.get("peak_cov", 0),
                "peak_features": current_peak_ft,
                "feature_delta": feature_delta,
                "new_corpus_promotions": new_promotions_count,
                "attributed_promotions": new_promotions_count - len(unmatched),
                "unmatched_promotions": len(unmatched),
                "attribution_coverage": attribution_cov,
                "operator_promotions": op_promos,
                "family_promotions": fam_promos,
                "total_stage_events": total_stages,
                "new_crash_candidates": len(new_crashes),
                "total_unique_crash_files": len(self.known_crashes),
                "telemetry_valid": telemetry_valid
            }

            metrics_file = epoch_dir / f"epoch_{epoch_id:03d}_metrics.json"
            with open(metrics_file, "w", encoding="utf-8") as f:
                json.dump(epoch_metrics, f, indent=2)
            self.epoch_metrics_history.append(epoch_metrics)

            # 9. Evaluate Saturation Monitor
            state, reason, recovery_actions = self.saturation_monitor.evaluate_epoch(
                epoch_idx=epoch_id,
                epoch_duration=float(self.epoch_seconds),
                new_corpus_promotions=new_promotions_count,
                feature_delta=feature_delta,
                new_stage_outcomes=total_stages,
                new_oracle_findings=0,
                unresolved_crash_candidates=len(new_crashes),
                telemetry_valid=(telemetry_valid if self.mode.startswith("adaptive") else True)
            )
            final_saturation_state = state.value
            print(f"  [Monitor] State: {state.value} | Reason: {reason}")

            # 10. Update Adaptive Policy
            if self.mode in ("adaptive", "adaptive_with_saturation"):
                boost = 1.5 if "INCREASE_EXPLORATION" in recovery_actions else 1.0
                self.policy.update_with_epoch_metrics(
                    operator_attempts_epoch=op_attempts_epoch,
                    operator_promotions_epoch=op_promos,
                    operator_stages_epoch=op_stages_epoch,
                    exploration_boost=boost
                )

            # 11. Handle Stopping Conditions
            if state in (self.SaturationState.SATURATED, self.SaturationState.BUDGET_STOP):
                stopping_reason = state.value
                break

            self.current_epoch += 1

        # Write Corpus Manifest
        with open(self.output_dir / "corpus_manifest.json", "w", encoding="utf-8") as f:
            json.dump(self.current_corpus_manifest, f, indent=2)

        # Write Campaign Summary & Report
        summary = self.generate_campaign_summary(stopping_reason, final_saturation_state)
        self.generate_campaign_report_markdown(summary)

        print("\n==========================================================")
        print(f" Campaign Concluded: {stopping_reason}")
        print(f" Total Executions : {self.total_executions:,}")
        print(f" Total Wall Time  : {self.total_elapsed_time:.1f}s")
        print(f" Final Corpus     : {len(self.current_corpus_manifest)} seeds")
        print(f" Crash Artifacts  : {len(self.known_crashes)}")
        print(f" Summary Written  : {self.output_dir / 'campaign_summary.json'}")
        print(f" Report Written   : {self.output_dir / 'campaign_report.md'}")
        print("==========================================================")

        return summary

    def generate_campaign_summary(self, stopping_reason: str, final_saturation_state: str) -> Dict[str, Any]:
        """Constructs campaign_summary.json structure."""
        summary = {
            "mode": self.mode,
            "target": self.target,
            "build_type": self.build_type,
            "stopping_reason": stopping_reason,
            "saturation_state": final_saturation_state,
            "total_epochs": len(self.epoch_metrics_history),
            "total_wall_time_seconds": self.total_elapsed_time,
            "total_executions": self.total_executions,
            "total_restarts": self.total_restarts,
            "initial_corpus_size": len(self.initial_corpus_manifest),
            "final_corpus_size": len(self.current_corpus_manifest),
            "total_corpus_promotions": len(self.current_corpus_manifest) - len(self.initial_corpus_manifest),
            "total_crash_artifacts": len(self.known_crashes),
            "saturation_summary": self.saturation_monitor.get_summary(),
            "epochs": self.epoch_metrics_history
        }

        with open(self.output_dir / "campaign_summary.json", "w", encoding="utf-8") as f:
            json.dump(summary, f, indent=2)

        return summary

    def generate_campaign_report_markdown(self, summary: Dict[str, Any]) -> None:
        """Generates comprehensive campaign_report.md markdown file."""
        lines = [
            f"# fastgltf Fuzzing Campaign Report — {self.mode.upper()}",
            "",
            f"- **Target Binary:** `{self.target}` (`{self.build_type}`)",
            f"- **Campaign Mode:** `{self.mode}`",
            f"- **Stopping Reason:** `{summary['stopping_reason']}`",
            f"- **Final Saturation State:** `{summary['saturation_state']}`",
            f"- **Total Wall Time:** {summary['total_wall_time_seconds']:.1f} seconds",
            f"- **Total Executions (All Child Subprocesses):** {summary['total_executions']:,}",
            f"- **Total Subprocess Restarts:** {summary['total_restarts']}",
            f"- **Corpus Growth:** {summary['initial_corpus_size']} -> {summary['final_corpus_size']} seeds (+{summary['total_corpus_promotions']})",
            f"- **Total Crash Artifacts:** {summary['total_crash_artifacts']}",
            "",
            "## 1. Epoch Progression Summary",
            "",
            "| Epoch | Duration (s) | Executions | Restarts | Peak Cov | Peak Ft | Delta Ft | Promotions | Attributed | Crashes |",
            "|-------|--------------|------------|----------|----------|---------|----------|------------|------------|---------|"
        ]

        for ep in summary["epochs"]:
            lines.append(
                f"| {ep['epoch']:03d} | {ep['duration_seconds']}s | {ep['executions']:,} | "
                f"{ep['restarts']} | {ep['peak_coverage']} | {ep['peak_features']} | "
                f"+{ep['feature_delta']} | {ep['new_corpus_promotions']} | "
                f"{ep['attributed_promotions']} ({ep['attribution_coverage']:.1%}) | "
                f"{ep['new_crash_candidates']} |"
            )

        lines.extend([
            "",
            "## 2. Saturation Monitor Decision Log",
            "",
            "| Epoch | State | Reason | Recovery Actions |",
            "|-------|-------|--------|------------------|"
        ])

        for hist in summary["saturation_summary"]["history"]:
            acts = ", ".join(hist.get("recovery_actions", [])) or "None"
            lines.append(f"| {hist['epoch']:03d} | {hist['next_state']} | {hist['reason']} | {acts} |")

        lines.extend([
            "",
            "## 3. Final Operator & Family Allocations",
            "",
            "```json",
            json.dumps(self.policy.export_policy_json(len(summary['epochs'])), indent=2),
            "```",
            ""
        ])

        with open(self.output_dir / "campaign_report.md", "w", encoding="utf-8") as f:
            f.write("\n".join(lines))


def main():
    parser = argparse.ArgumentParser(description="fastgltf Adaptive Hybrid Campaign Manager")
    parser.add_argument("--config", type=Path, default=Path(__file__).resolve().parent / "campaign_policy.example.json",
                        help="Path to campaign policy JSON config")
    parser.add_argument("--mode", choices=["fixed", "adaptive", "fixed_with_saturation", "adaptive_with_saturation"],
                        default=None, help="Campaign mode override")
    parser.add_argument("--target", default=None, help="Target binary (e.g. deep_fuzzer)")
    parser.add_argument("--build", default=None, help="Build type (e.g. asan, release-asan)")
    parser.add_argument("--output-dir", type=Path, default=Path(__file__).resolve().parent.parent / "findings" / "campaign_runs" / "run_01",
                        help="Campaign output directory")
    parser.add_argument("--seed-dir", type=Path, default=Path(__file__).resolve().parent.parent / "corpus" / "seed",
                        help="Initial seed corpus directory")
    parser.add_argument("--epoch-seconds", type=int, default=None, help="Duration of each epoch in seconds")
    parser.add_argument("--hard-max-seconds", type=int, default=None, help="Hard maximum campaign runtime in seconds")
    parser.add_argument("--max-epochs", type=int, default=100, help="Maximum number of epochs to run")
    parser.add_argument("--seed", type=int, default=None, help="Fuzzer seed override")

    args = parser.parse_args()

    cli_overrides = {
        "mode": args.mode,
        "target": args.target,
        "build": args.build,
        "epoch_seconds": args.epoch_seconds,
        "hard_max_runtime_seconds": args.hard_max_seconds,
        "seed": args.seed,
    }

    manager = CampaignManager(
        config_path=args.config,
        output_dir=args.output_dir,
        cli_overrides=cli_overrides
    )

    manager.initialize_corpus(args.seed_dir)
    manager.run_campaign(max_epochs=args.max_epochs)


if __name__ == "__main__":
    main()

