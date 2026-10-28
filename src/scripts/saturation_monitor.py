#!/usr/bin/env python3
"""
Conservative Saturation State Machine & Plateau Recovery Manager for fastgltf Fuzzer.
Implements the multi-signal stopping criteria specified in Section F of the design document:
- ACTIVE: steady progression
- PLATEAU_SUSPECTED: consecutive low-yield epochs observed
- RECOVERY: bounded plateau-breaking phase attempting recovery actions
- SATURATED: plateau persisted through recovery, minimum runtime met, and signals reliable
- BUDGET_STOP: hard budget reached
- ERROR: telemetry is missing or unparseable; fails safely without declaring saturation
"""

from enum import Enum
from typing import Dict, Any, List, Optional, Tuple


class SaturationState(Enum):
    ACTIVE = "ACTIVE"
    PLATEAU_SUSPECTED = "PLATEAU_SUSPECTED"
    RECOVERY = "RECOVERY"
    SATURATED = "SATURATED"
    BUDGET_STOP = "BUDGET_STOP"
    ERROR = "ERROR"


class SaturationMonitor:
    def __init__(self, config: Dict[str, Any]):
        sat_cfg = config.get("saturation", {})
        camp_cfg = config.get("campaign", {})

        self.enabled: bool = sat_cfg.get("enabled", True)
        self.low_yield_threshold_epochs: int = sat_cfg.get("low_yield_epochs_to_suspect_plateau", 3)
        self.min_promotions_per_epoch: int = sat_cfg.get("minimum_new_corpus_promotions_per_epoch", 1)
        self.min_feature_delta_per_epoch: int = sat_cfg.get("minimum_feature_delta_per_epoch", 1)
        self.require_stage_check: bool = sat_cfg.get("require_stage_or_oracle_progress_check", True)

        self.recovery_epochs_allowed: int = sat_cfg.get("recovery_epochs", 1)
        self.recovery_epoch_seconds: int = sat_cfg.get("recovery_epoch_seconds", 600)
        self.recovery_increase_exploration: bool = sat_cfg.get("recovery_increase_exploration", True)
        self.recovery_seed_refresh: bool = sat_cfg.get("recovery_seed_refresh", True)

        self.min_runtime_seconds: int = camp_cfg.get("minimum_runtime_before_saturation_seconds", 1800)
        self.hard_max_runtime_seconds: int = camp_cfg.get("hard_max_runtime_seconds", 7200)
        self.stop_only_with_complete_telemetry: bool = sat_cfg.get("stop_only_with_complete_telemetry", True)
        self.unresolved_crash_blocks_stop: bool = sat_cfg.get("unresolved_crash_blocks_saturation_stop", True)

        # Internal state
        self.current_state: SaturationState = SaturationState.ACTIVE
        self.low_yield_streak: int = 0
        self.recovery_epochs_remaining: int = 0
        self.recovery_rounds_attempted: int = 0
        self.total_elapsed_seconds: float = 0.0
        self.history: List[Dict[str, Any]] = []

    def evaluate_epoch(self,
                       epoch_idx: int,
                       epoch_duration: float,
                       new_corpus_promotions: int,
                       feature_delta: int,
                       new_stage_outcomes: int = 0,
                       new_oracle_findings: int = 0,
                       unresolved_crash_candidates: int = 0,
                       telemetry_valid: bool = True) -> Tuple[SaturationState, str, List[str]]:
        """
        Evaluate an epoch and determine next state, decision reason, and recovery actions.
        Returns (next_state, decision_reason, list_of_recovery_actions)
        """
        self.total_elapsed_seconds += epoch_duration
        recovery_actions: List[str] = []

        # Record epoch metrics in history
        record = {
            "epoch": epoch_idx,
            "duration": epoch_duration,
            "new_corpus_promotions": new_corpus_promotions,
            "feature_delta": feature_delta,
            "new_stage_outcomes": new_stage_outcomes,
            "new_oracle_findings": new_oracle_findings,
            "unresolved_crash_candidates": unresolved_crash_candidates,
            "telemetry_valid": telemetry_valid,
            "previous_state": self.current_state.value
        }

        # 1. Check Hard Budget Cap
        if self.total_elapsed_seconds >= self.hard_max_runtime_seconds:
            self.current_state = SaturationState.BUDGET_STOP
            reason = f"Hard maximum campaign runtime of {self.hard_max_runtime_seconds}s reached ({self.total_elapsed_seconds:.1f}s elapsed)."
            record["next_state"] = self.current_state.value
            record["reason"] = reason
            self.history.append(record)
            return self.current_state, reason, recovery_actions

        # 2. Check Telemetry Completeness
        if self.stop_only_with_complete_telemetry and not telemetry_valid:
            if self.current_state != SaturationState.ERROR:
                self.current_state = SaturationState.ACTIVE  # Continue safely, never declare saturation
            reason = "Telemetry missing, incomplete, or corrupted; cannot soundly evaluate saturation."
            record["next_state"] = self.current_state.value
            record["reason"] = reason
            self.history.append(record)
            return self.current_state, reason, recovery_actions

        # 3. If saturation monitoring is disabled in config, always remain ACTIVE
        if not self.enabled:
            self.current_state = SaturationState.ACTIVE
            reason = "Saturation monitoring disabled in configuration; continuing fuzzing."
            record["next_state"] = self.current_state.value
            record["reason"] = reason
            self.history.append(record)
            return self.current_state, reason, recovery_actions

        # 4. Multi-signal progress assessment
        has_corpus_progress = (new_corpus_promotions >= self.min_promotions_per_epoch)
        has_feature_progress = (feature_delta >= self.min_feature_delta_per_epoch)
        has_stage_progress = (new_stage_outcomes > 0 or new_oracle_findings > 0)

        is_low_yield = (not has_corpus_progress) and (not has_feature_progress)
        if self.require_stage_check and has_stage_progress:
            is_low_yield = False

        record["is_low_yield"] = is_low_yield

        # 5. State Machine Transition Logic
        if self.current_state == SaturationState.ACTIVE:
            if is_low_yield:
                self.low_yield_streak += 1
                if self.low_yield_streak >= self.low_yield_threshold_epochs:
                    self.current_state = SaturationState.RECOVERY
                    self.recovery_epochs_remaining = self.recovery_epochs_allowed
                    self.recovery_rounds_attempted += 1
                    reason = f"Plateau suspected: {self.low_yield_streak} consecutive low-yield epochs. Triggering RECOVERY phase."
                    if self.recovery_increase_exploration:
                        recovery_actions.append("INCREASE_EXPLORATION")
                    if self.recovery_seed_refresh:
                        recovery_actions.append("REFRESH_SEED_TEMPLATES")
                else:
                    reason = f"Low-yield epoch observed ({self.low_yield_streak}/{self.low_yield_threshold_epochs}); continuing ACTIVE."
            else:
                self.low_yield_streak = 0
                reason = "Progress detected (corpus promotions or new coverage features); remaining ACTIVE."

        elif self.current_state == SaturationState.RECOVERY:
            self.recovery_epochs_remaining -= 1
            if not is_low_yield:
                # Progress was restored by recovery!
                self.current_state = SaturationState.ACTIVE
                self.low_yield_streak = 0
                reason = "Recovery successful: progress restored during recovery epoch. Returning to ACTIVE state."
            elif self.recovery_epochs_remaining > 0:
                reason = f"Recovery in progress ({self.recovery_epochs_remaining} recovery epochs remaining)."
                if self.recovery_increase_exploration:
                    recovery_actions.append("INCREASE_EXPLORATION")
            else:
                # Recovery exhausted without restoring progress
                can_stop_saturation = True
                block_reasons = []

                if self.total_elapsed_seconds < self.min_runtime_seconds:
                    can_stop_saturation = False
                    block_reasons.append(f"elapsed time {self.total_elapsed_seconds:.1f}s < minimum runtime {self.min_runtime_seconds}s")

                if self.unresolved_crash_blocks_stop and unresolved_crash_candidates > 0:
                    can_stop_saturation = False
                    block_reasons.append(f"{unresolved_crash_candidates} unresolved crash candidate(s) pending triage")

                if can_stop_saturation:
                    self.current_state = SaturationState.SATURATED
                    reason = f"Campaign SATURATED: {self.low_yield_threshold_epochs} low-yield epochs persisted through recovery. All stopping criteria verified."
                else:
                    # Reset low yield streak and continue fuzzing because constraints prevent stopping
                    self.current_state = SaturationState.ACTIVE
                    self.low_yield_streak = 0
                    reason = f"Recovery failed but saturation blocked ({', '.join(block_reasons)}). Returning to ACTIVE."

        record["next_state"] = self.current_state.value
        record["reason"] = reason
        record["recovery_actions"] = recovery_actions
        self.history.append(record)

        return self.current_state, reason, recovery_actions

    def get_summary(self) -> Dict[str, Any]:
        return {
            "current_state": self.current_state.value,
            "total_elapsed_seconds": self.total_elapsed_seconds,
            "low_yield_streak": self.low_yield_streak,
            "recovery_rounds_attempted": self.recovery_rounds_attempted,
            "total_epochs_monitored": len(self.history),
            "history": self.history
        }

