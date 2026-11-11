# Experimental Methodology & Statistical Evaluation

## 1. Research Question

> **Central Hypothesis**: Under a constrained fuzzing budget (e.g. 30 minutes), does target-specific structure-aware glTF/GLB mutation reach deeper fastgltf behavior, achieve higher library code coverage, and produce better security findings than ordinary byte-level coverage-guided fuzzing?

---

## 2. Experimental Design

To ensure scientific rigor and fair empirical comparison:
1. **Identical Baseline Snapshot**:
   Every trial across all arms begins with the exact same initial merged seed corpus (`corpus/merged/initial`, 14 unique units).
2. **Pinned Target Binary**:
   All trials run the exact same target executable (`build-asan/deep_fuzzer`), compiled from pinned `fastgltf v0.9.1` (commit `705564d`) under Clang 18.1.3 with ASan and UBSan.
3. **Controlled Arms**:
   - **Arm A (`byte`)**: Standard libFuzzer mutation (`LLVMFuzzerMutate`) with dictionary.
   - **Arm B (`struct`)**: Pure structure-aware mutation (GLB + JSON AST + invariant breaking).
   - **Arm C (`hybrid`)**: Multi-strategy hybrid arm (25% byte, 25% repaired struct, 40% invariant-breaking, 10% procedural generation).
4. **Repetitions & Budget**:
   - **5 independent trials** per arm (15 trials total).
   - **30-minute time budget** per trial.
   - Distinct pseudo-random seed per trial.

---

## 3. Evaluation Metrics

For each trial, the campaign infrastructure records:

| Metric | Source | Description |
| :--- | :--- | :--- |
| **fastgltf Line Coverage** | `llvm-cov report` | Percentage of fastgltf source lines exercised (strictly excluding simdjson). |
| **Total Executions & Exec/s** | libFuzzer log | Throughput over the trial duration. |
| **Parse Success Rate** | `Telemetry` | Percentage of inputs that produced a valid `fastgltf::Asset`. |
| **Container Depth Reach** | `Telemetry` | Percentage of inputs reaching buffers, bufferViews, accessors. |
| **Deep Accessor Exercise Count**| `Telemetry` | Number of accessor tools actually exercised. |
| **Unique Target Crashes** | `scripts/triage.sh` | Number of distinct deduplicated crash signatures. |

---

## 4. Statistical Analysis Plan

Because fuzzing outcomes exhibit variance across trials:
1. **Summary Statistics**:
   - Report **Median** and **Interquartile Range (IQR)**, as well as Min and Max.
   - Avoid relying purely on the arithmetic mean.
2. **Significance Testing**:
   - Use the **Mann-Whitney U test** (Wilcoxon rank-sum test) to compare differences between pairs of arms (e.g., `hybrid` vs `byte`).
3. **Reachability Analysis**:
   - Compare the percentage of inputs rejected at container parsing versus inputs reaching deep accessor execution.
   - A demonstration that structure awareness reduces outer syntax rejection from ~85% down to ~35% provides definitive positive evidence for the research hypothesis, even if no zero-day crash occurs in a given trial.
