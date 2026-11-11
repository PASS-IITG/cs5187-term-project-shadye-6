#!/usr/bin/env bash
set -euo pipefail

# Multi-trial campaign manager for fastgltf fuzzing evaluation
# Usage: ./scripts/campaign.sh [options]
#   --mode        : byte | struct | hybrid | all (default: all)
#   --minutes     : Time budget per trial in minutes (default: 30)
#   --trials      : Number of independent trials per arm (default: 5)
#   --target      : deep_fuzzer | parser_fuzzer (default: deep_fuzzer)
#   --build       : release-asan | asan (default: release-asan)
#   --parallel    : Launch trials concurrently (default: false)
#   --interleave  : Interleave arm execution to avoid time/thermal confounding (default: true)
#   --no-interleave : Run arm trials in contiguous batches

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

CAMPAIGN_MODE="all"
MINUTES=30
TRIALS=5
TARGET="deep_fuzzer"
BUILD_TYPE="release-asan"
PARALLEL=false
INTERLEAVE=true

while [[ $# -gt 0 ]]; do
    case "$1" in
        --mode) CAMPAIGN_MODE="$2"; shift 2 ;;
        --minutes) MINUTES="$2"; shift 2 ;;
        --trials) TRIALS="$2"; shift 2 ;;
        --target) TARGET="$2"; shift 2 ;;
        --build) BUILD_TYPE="$2"; shift 2 ;;
        --parallel) PARALLEL=true; shift ;;
        --interleave) INTERLEAVE=true; shift ;;
        --no-interleave) INTERLEAVE=false; shift ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

DURATION_SEC=$((MINUTES * 60))
SEED_CORPUS="${ROOT_DIR}/corpus/merged/initial"

# Ensure binary exists, build if missing
BIN="${ROOT_DIR}/build-${BUILD_TYPE}/${TARGET}"
if [ ! -f "${BIN}" ]; then
    echo "Binary not found: ${BIN}. Building ${BUILD_TYPE} configuration..."
    "${SCRIPT_DIR}/build.sh" "${BUILD_TYPE}"
fi

# Ensure initial merged seed corpus exists
if [ ! -d "${SEED_CORPUS}" ] || [ -z "$(ls -A "${SEED_CORPUS}")" ]; then
    echo "Preparing initial merged seed corpus..."
    python3 "${SCRIPT_DIR}/prepare_seeds.py"
    "${SCRIPT_DIR}/merge_corpus.sh" "${TARGET}" "${SEED_CORPUS}" "${ROOT_DIR}/corpus/seed"
fi

MODES=()
if [ "${CAMPAIGN_MODE}" = "all" ]; then
    MODES=("byte" "struct" "hybrid")
else
    MODES=("${CAMPAIGN_MODE}")
fi

RESULTS_DIR="${ROOT_DIR}/findings/trials"
mkdir -p "${RESULTS_DIR}" "${ROOT_DIR}/findings/crashes"

echo "=========================================================="
echo " Launching Research Campaign"
echo " Target Library: fastgltf v0.9.1 (commit 705564d)"
echo " Modes         : ${MODES[*]}"
echo " Trials / Arm  : ${TRIALS}"
echo " Budget / Trial: ${MINUTES} minutes (${DURATION_SEC}s)"
echo " Target Binary : ${TARGET} (${BUILD_TYPE})"
echo " Interleaved   : ${INTERLEAVE}"
echo " Parallel      : ${PARALLEL}"
echo "=========================================================="

# Record campaign metadata
METADATA_FILE="${RESULTS_DIR}/campaign_metadata.json"
cat << EOF > "${METADATA_FILE}"
{
  "target": "${TARGET}",
  "build_type": "${BUILD_TYPE}",
  "fastgltf_version": "v0.9.1",
  "fastgltf_commit": "705564d4d54500ae88befb0db9e361e447923655",
  "compiler": "$(clang++ --version | head -n 1)",
  "os": "$(uname -srm)",
  "duration_seconds_per_trial": ${DURATION_SEC},
  "trials_per_arm": ${TRIALS},
  "modes": $(printf '%s\n' "${MODES[@]}" | jq -R . | jq -s .),
  "interleaved": ${INTERLEAVE},
  "parallel": ${PARALLEL},
  "start_time": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
}
EOF

run_trial() {
    local mode="$1"
    local trial_id="$2"
    local trial_seed=$((100000 + trial_id * 1000 + RANDOM % 999))
    local trial_dir="${RESULTS_DIR}/${mode}_trial_${trial_id}"
    local corpus_dir="${trial_dir}/corpus"
    local crash_dir="${trial_dir}/crashes"
    local log_file="${trial_dir}/trial.log"
    local telemetry_file="${trial_dir}/telemetry.json"

    mkdir -p "${corpus_dir}" "${crash_dir}"
    # Seed with standard initial merged corpus snapshot
    cp "${SEED_CORPUS}"/* "${corpus_dir}/" 2>/dev/null || true

    echo "--- Running Arm: ${mode} | Trial: ${trial_id}/${TRIALS} (Seed: ${trial_seed}) ---"

    local start_time
    start_time=$(date +%s)
    local end_time=$((start_time + DURATION_SEC))

    export FUZZ_MODE="${mode}"
    export TELEMETRY_LOG="${telemetry_file}"
    export ASAN_OPTIONS="abort_on_error=1:detect_leaks=0:symbolize=1"
    export UBSAN_OPTIONS="print_stacktrace=1:halt_on_error=1:abort_on_error=1:symbolize=1"

    local bin="${ROOT_DIR}/build-${BUILD_TYPE}/${TARGET}"
    local restart_count=0

    # Restart loop until time budget is exhausted
    while true; do
        local now
        now=$(date +%s)
        local remaining=$((end_time - now))
        if [ ${remaining} -le 0 ]; then
            break
        fi

        echo "  [${mode} #${trial_id}] Launching (remaining: ${remaining}s, restarts: ${restart_count})"
        set +e
        "${bin}" "${corpus_dir}" \
            "-max_total_time=${remaining}" \
            "-timeout=10" \
            "-seed=${trial_seed}" \
            "-dict=${ROOT_DIR}/corpus/gltf.dict" \
            "-artifact_prefix=${crash_dir}/" \
            "-len_control=0" \
            "-max_len=65536" \
            >> "${log_file}" 2>&1
        local exit_status=$?
        set -e

        if [ ${exit_status} -eq 0 ]; then
            # Completed budget without crash
            break
        else
            restart_count=$((restart_count + 1))
            echo "  [${mode} #${trial_id}] Target exited with code ${exit_status}. Preserving crash artifacts and resuming..."
            # Check for crash artifacts and copy to central findings
            find "${crash_dir}" -type f -name "crash-*" -exec cp {} "${ROOT_DIR}/findings/crashes/" \; 2>/dev/null || true
            sleep 1
        fi
    done

    local final_corpus_count
    final_corpus_count=$(find "${corpus_dir}" -type f | wc -l)
    local crash_count
    crash_count=$(find "${crash_dir}" -type f -name "crash-*" | wc -l)

    echo "  Completed [${mode} #${trial_id}]: Corpus size: ${final_corpus_count}, Crashes: ${crash_count}"
}

# Arm trial scheduling
if [ "${INTERLEAVE}" = "true" ] && [ ${#MODES[@]} -gt 1 ]; then
    echo "=========================================================="
    echo " Interleaved Arm Execution Mode"
    echo " Eliminates sequential time-of-day and thermal confounding"
    echo "=========================================================="
    for t in $(seq 1 "${TRIALS}"); do
        echo "=== Round ${t}/${TRIALS}: Executing trial across arms ==="
        if [ "${PARALLEL}" = "true" ]; then
            pids=()
            for m in "${MODES[@]}"; do
                run_trial "${m}" "${t}" &
                pids+=($!)
            done
            for pid in "${pids[@]}"; do
                wait "$pid" || true
            done
        else
            for m in "${MODES[@]}"; do
                run_trial "${m}" "${t}"
            done
        fi
    done
else
    for m in "${MODES[@]}"; do
        echo "=========================================================="
        echo " Starting Arm: ${m} (${TRIALS} trials, ${MINUTES}m budget each)"
        echo "=========================================================="
        if [ "${PARALLEL}" = "true" ]; then
            echo "  [${m}] Launching ${TRIALS} trials concurrently..."
            pids=()
            for t in $(seq 1 "${TRIALS}"); do
                run_trial "${m}" "${t}" &
                pids+=($!)
            done
            for pid in "${pids[@]}"; do
                wait "$pid" || true
            done
            echo "=== Completed Arm: ${m} (all ${TRIALS} trials finished) ==="
        else
            for t in $(seq 1 "${TRIALS}"); do
                run_trial "${m}" "${t}"
            done
        fi
    done
fi

echo "=========================================================="
echo " Campaign Completed!"
echo " Results stored in: ${RESULTS_DIR}"
echo "=========================================================="

echo "Running crash triage..."
python3 "${SCRIPT_DIR}/triage.py" "${ROOT_DIR}/findings/crashes" "${BIN}" || true

if [ -f "${SCRIPT_DIR}/evaluate_campaign.py" ]; then
    echo "Generating campaign evaluation summary..."
    python3 "${SCRIPT_DIR}/evaluate_campaign.py" || true
fi
