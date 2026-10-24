# Campaign Evaluation Results & Comparative Analysis

- **Target Library**: fastgltf v0.9.1 (commit `705564d`)
- **Build Configuration**: asan (Ubuntu clang version 18.1.3 (1ubuntu1))
- **Duration per trial**: 30 minutes (1800s)
- **Trials per arm**: 5
- **OS/Platform**: Linux 6.6.87.2-microsoft-standard-WSL2 x86_64

## 1. Summary Statistics per Arm (Median [IQR])

| Arm | Corpus Units (Median [IQR]) | Unique Bugs (Median [IQR]) | Crash Events / Restarts (Median [IQR]) | Total Execs (Median) | Exec/s (Median) |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **`byte`** | 375.0 [160.0] | 17.0 [12.0] | 17.0 [12.0] | 197,088 | 109 |
| **`struct`** | 291.0 [269.0] | 6.0 [33.0] | 6.0 [33.0] | 181,934 | 101 |
| **`hybrid`** | 428.0 [91.0] | 38.0 [12.0] | 38.0 [12.0] | 262,739 | 145 |

---

## 2. Trial-by-Trial Breakdown

### Arm: `byte`

| Trial ID | Corpus Count | Unique Bugs | Crash Events | Total Executions | Exec/s | Restarts |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| `byte_trial_1` | 243 | 4 | 4 | 160,081 | 88 | 606 |
| `byte_trial_2` | 535 | 45 | 45 | 409,917 | 227 | 352 |
| `byte_trial_3` | 308 | 8 | 8 | 178,333 | 99 | 517 |
| `byte_trial_4` | 375 | 20 | 20 | 197,088 | 109 | 442 |
| `byte_trial_5` | 468 | 17 | 17 | 242,470 | 134 | 381 |

### Arm: `struct`

| Trial ID | Corpus Count | Unique Bugs | Crash Events | Total Executions | Exec/s | Restarts |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| `struct_trial_1` | 252 | 5 | 5 | 166,369 | 92 | 612 |
| `struct_trial_2` | 180 | 3 | 3 | 72,489 | 40 | 375 |
| `struct_trial_3` | 521 | 41 | 41 | 342,149 | 190 | 388 |
| `struct_trial_4` | 291 | 6 | 6 | 181,934 | 101 | 562 |
| `struct_trial_5` | 525 | 38 | 38 | 250,432 | 139 | 366 |

### Arm: `hybrid`

| Trial ID | Corpus Count | Unique Bugs | Crash Events | Total Executions | Exec/s | Restarts |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| `hybrid_trial_1` | 398 | 18 | 18 | 153,293 | 85 | 288 |
| `hybrid_trial_2` | 424 | 38 | 38 | 262,739 | 145 | 428 |
| `hybrid_trial_3` | 578 | 41 | 41 | 344,073 | 191 | 374 |
| `hybrid_trial_4` | 428 | 29 | 29 | 212,196 | 117 | 481 |
| `hybrid_trial_5` | 515 | 53 | 53 | 290,125 | 161 | 370 |

## 3. Methodological Notes

- **Total Executions**: Aggregated across all restart runs in each trial log, rather than taking solely the final restart before timeout.
- **Unique Bugs vs Crash Events**: Unique bugs represent deduplicated finding signatures derived via triage; Crash Events indicate raw process terminations/restarts caused by repeated assert aborts.
- **Statistical Metrics**: Non-parametric Median and Interquartile Range (IQR = Q3 - Q1) are reported per guidelines for multi-trial fuzzing evaluations.
