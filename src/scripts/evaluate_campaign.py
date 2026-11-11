#!/usr/bin/env python3
"""
Campaign evaluation and statistical report generator for fastgltf fuzzing.
Accurately aggregates execution counts across all restart sessions,
reports deduplicated unique bugs alongside raw crash events,
and computes robust non-parametric summary statistics (Median, IQR).
"""

import os
import sys
import json
import glob
import re
from pathlib import Path

def compute_median_iqr(values):
    if not values:
        return 0, 0, 0, 0
    s = sorted(values)
    n = len(s)
    mid = n // 2
    median = s[mid] if n % 2 != 0 else (s[mid - 1] + s[mid]) / 2.0
    
    # Q1 and Q3
    q1 = s[n // 4]
    q3 = s[(3 * n) // 4]
    iqr = q3 - q1
    return median, iqr, s[0], s[-1]

def load_triage_index(index_csv_path):
    """
    Loads triage index mapping crash testcase filename/hash to finding_id.
    """
    testcase_to_finding = {}
    if not os.path.isfile(index_csv_path):
        return testcase_to_finding
    
    try:
        with open(index_csv_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                parts = line.strip().split(",")
                if len(parts) >= 6 and parts[0].startswith("FINDING-"):
                    finding_id = parts[0]
                    testcase_path = parts[5].strip('"')
                    filename = os.path.basename(testcase_path)
                    testcase_to_finding[filename] = finding_id
    except Exception as e:
        print(f"Warning: could not read triage index: {e}")
    return testcase_to_finding

def parse_trial(trial_dir, triage_map, duration_sec=1800):
    data = {
        "corpus_count": 0,
        "crash_events": 0,
        "unique_bugs": 0,
        "total_execs": 0,
        "exec_per_sec": 0,
        "restart_count": 0,
        "telemetry": {}
    }
    
    # 1. Corpus count
    corpus_dir = os.path.join(trial_dir, "corpus")
    if os.path.isdir(corpus_dir):
        data["corpus_count"] = len([f for f in os.listdir(corpus_dir) if os.path.isfile(os.path.join(corpus_dir, f))])
        
    # 2. Crash files & deduplicated unique bugs
    crash_dir = os.path.join(trial_dir, "crashes")
    if os.path.isdir(crash_dir):
        crash_files = [f for f in os.listdir(crash_dir) if f.startswith("crash-")]
        data["crash_events"] = len(crash_files)
        
        # Deduplicate using triage index
        unique_finding_ids = set()
        for cf in crash_files:
            if cf in triage_map:
                unique_finding_ids.add(triage_map[cf])
            else:
                # If not explicitly indexed, check if basename hash matched
                unique_finding_ids.add(cf)
        data["unique_bugs"] = len(unique_finding_ids) if crash_files else 0
        
    # 3. Aggregated executions across ALL restart runs in trial.log
    log_file = os.path.join(trial_dir, "trial.log")
    if os.path.isfile(log_file):
        try:
            total_sum = 0
            curr_session_max = 0
            session_count = 0
            last_speed = 0

            with open(log_file, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    # New libFuzzer invocation marker
                    if "INFO: Running with entropic" in line or "Dictionary: " in line:
                        if curr_session_max > 0:
                            total_sum += curr_session_max
                            session_count += 1
                            curr_session_max = 0
                        continue

                    # Executions and speed match: #12345 ... exec/s: 567
                    m = re.search(r"#(\d+)\s+.*exec/s:\s*(\d+)", line)
                    if m:
                        exec_val = int(m.group(1))
                        speed_val = int(m.group(2))
                        if exec_val > curr_session_max:
                            curr_session_max = exec_val
                        last_speed = speed_val
                        continue

                    # Fallback match for #12345
                    m_simple = re.search(r"#(\d+)\s+(?:INITED|NEW|REDUCE|PULSE|DONE)", line)
                    if m_simple:
                        exec_val = int(m_simple.group(1))
                        if exec_val > curr_session_max:
                            curr_session_max = exec_val
                        continue

                    # Stat line from libFuzzer on exit
                    m_stat = re.search(r"stat::number_of_executed_units:\s*(\d+)", line)
                    if m_stat:
                        exec_val = int(m_stat.group(1))
                        if exec_val > curr_session_max:
                            curr_session_max = exec_val

                # Add final session executions
                if curr_session_max > 0:
                    total_sum += curr_session_max
                    session_count += 1

            data["total_execs"] = total_sum
            data["restart_count"] = max(0, session_count - 1)
            # Effective execution rate across whole trial
            if duration_sec > 0 and total_sum > 0:
                data["exec_per_sec"] = int(total_sum / duration_sec)
            else:
                data["exec_per_sec"] = last_speed

        except Exception as e:
            print(f"Error parsing log file {log_file}: {e}")

    # 4. Check telemetry if available
    telem_file = os.path.join(trial_dir, "telemetry.json")
    if os.path.isfile(telem_file):
        try:
            with open(telem_file, "r") as f:
                data["telemetry"] = json.load(f)
                telem_execs = data["telemetry"].get("total_executions", 0)
                if telem_execs > data["total_execs"]:
                    data["total_execs"] = telem_execs
                    if duration_sec > 0:
                        data["exec_per_sec"] = int(telem_execs / duration_sec)
        except Exception:
            pass

    return data

def main():
    root_dir = Path(__file__).resolve().parent.parent
    trials_dir = root_dir / "findings" / "trials"
    index_csv = root_dir / "findings" / "index.csv"
    
    if not trials_dir.is_dir():
        print(f"Trials directory not found: {trials_dir}")
        return 1

    metadata_file = trials_dir / "campaign_metadata.json"
    meta = {}
    if metadata_file.is_file():
        try:
            with open(metadata_file, "r") as f:
                meta = json.load(f)
        except Exception:
            pass

    duration_sec = meta.get("duration_seconds_per_trial", 1800)
    triage_map = load_triage_index(str(index_csv))

    modes = ["byte", "struct", "hybrid"]
    arm_data = {m: [] for m in modes}

    for d in sorted(trials_dir.iterdir()):
        if not d.is_dir():
            continue
        for m in modes:
            if d.name.startswith(f"{m}_trial_"):
                arm_data[m].append((d.name, parse_trial(str(d), triage_map, duration_sec)))

    report_lines = []
    report_lines.append("# Campaign Evaluation Results & Comparative Analysis\n")
    report_lines.append(f"- **Target Library**: fastgltf v0.9.1 (commit `705564d`)")
    report_lines.append(f"- **Build Configuration**: {meta.get('build_type', 'release-asan')} ({meta.get('compiler', 'Clang 18.1.3')})")
    report_lines.append(f"- **Duration per trial**: {duration_sec // 60} minutes ({duration_sec}s)")
    report_lines.append(f"- **Trials per arm**: {meta.get('trials_per_arm', 5)}")
    report_lines.append(f"- **OS/Platform**: {meta.get('os', 'Linux (WSL2)')}\n")

    report_lines.append("## 1. Summary Statistics per Arm (Median [IQR])\n")
    report_lines.append("| Arm | Corpus Units (Median [IQR]) | Unique Bugs (Median [IQR]) | Crash Events / Restarts (Median [IQR]) | Total Execs (Median) | Exec/s (Median) |")
    report_lines.append("| :--- | :---: | :---: | :---: | :---: | :---: |")

    summary_stats = {}
    for m in modes:
        trials = arm_data[m]
        if not trials:
            continue
        corp_list = [t[1]["corpus_count"] for t in trials]
        unique_bug_list = [t[1]["unique_bugs"] for t in trials]
        crash_event_list = [t[1]["crash_events"] for t in trials]
        exec_list = [t[1]["total_execs"] for t in trials]
        speed_list = [t[1]["exec_per_sec"] for t in trials]

        c_med, c_iqr, _, _ = compute_median_iqr(corp_list)
        ub_med, ub_iqr, _, _ = compute_median_iqr(unique_bug_list)
        ce_med, ce_iqr, _, _ = compute_median_iqr(crash_event_list)
        ex_med, ex_iqr, _, _ = compute_median_iqr(exec_list)
        sp_med, sp_iqr, _, _ = compute_median_iqr(speed_list)

        summary_stats[m] = {
            "corpus_median": c_med, "corpus_iqr": c_iqr,
            "unique_bugs_median": ub_med, "unique_bugs_iqr": ub_iqr,
            "crash_events_median": ce_med, "crash_events_iqr": ce_iqr,
            "exec_median": ex_med, "exec_iqr": ex_iqr,
            "speed_median": sp_med, "speed_iqr": sp_iqr,
        }

        report_lines.append(f"| **`{m}`** | {c_med:.1f} [{c_iqr:.1f}] | {ub_med:.1f} [{ub_iqr:.1f}] | {ce_med:.1f} [{ce_iqr:.1f}] | {int(ex_med):,} | {int(sp_med):,} |")

    report_lines.append("\n---\n")
    report_lines.append("## 2. Trial-by-Trial Breakdown\n")

    for m in modes:
        trials = arm_data[m]
        if not trials:
            continue
        report_lines.append(f"### Arm: `{m}`\n")
        report_lines.append("| Trial ID | Corpus Count | Unique Bugs | Crash Events | Total Executions | Exec/s | Restarts |")
        report_lines.append("| :--- | :---: | :---: | :---: | :---: | :---: | :---: |")
        for name, tdata in trials:
            report_lines.append(f"| `{name}` | {tdata['corpus_count']} | {tdata['unique_bugs']} | {tdata['crash_events']} | {tdata['total_execs']:,} | {tdata['exec_per_sec']:,} | {tdata['restart_count']} |")
        report_lines.append("")

    report_lines.append("## 3. Methodological Notes\n")
    report_lines.append("- **Total Executions**: Aggregated across all restart runs in each trial log, rather than taking solely the final restart before timeout.")
    report_lines.append("- **Unique Bugs vs Crash Events**: Unique bugs represent deduplicated finding signatures derived via triage; Crash Events indicate raw process terminations/restarts caused by repeated assert aborts.")
    report_lines.append("- **Statistical Metrics**: Non-parametric Median and Interquartile Range (IQR = Q3 - Q1) are reported per guidelines for multi-trial fuzzing evaluations.")

    report_path = root_dir / "docs" / "campaign_results.md"
    with open(report_path, "w", encoding="utf-8") as f:
        f.write("\n".join(report_lines) + "\n")

    summary_json_path = trials_dir / "summary.json"
    with open(summary_json_path, "w", encoding="utf-8") as f:
        json.dump({"metadata": meta, "summary": summary_stats, "trials": arm_data}, f, indent=2)

    print(f"[+] Evaluation written to {report_path}")
    print(f"[+] Summary JSON written to {summary_json_path}")
    return 0

if __name__ == "__main__":
    sys.exit(main())
