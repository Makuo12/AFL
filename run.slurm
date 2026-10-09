#!/bin/bash
#SBATCH --job-name=project_afl_run
#SBATCH --partition=normal_q
#SBATCH --account=fuzzing
#SBATCH --constraint=intel
#SBATCH --time=03:00:00
#SBATCH --ntasks=1
#SBATCH --cpus-per-task=1
#SBATCH --mem-per-cpu=4G
#SBATCH --output=./logs/fuzz-%j.log
#SBATCH --error=./logs/fuzz-%j.log
#SBATCH --array=1-3

set -euo pipefail
export AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1
export AFL_SKIP_CPUFREQ=1
export AFL_NO_UI=1
export AFL_NO_FORKSRV=1  

FUZZ_SECONDS=$((2 * 3600))
TRACE="main.trace"
ORACLE="main.oracle"

if [[ "${1:-}" = "arc" ]]; then
    module load LLVM/20.1.8-GCCcore-14.3.0
    module load GCCcore/14.3.0

    ID="${SLURM_ARRAY_JOB_ID:-${SLURM_JOB_ID:-0}}_${SLURM_ARRAY_TASK_ID:-0}"
    FULL_ID="${PROGRAM}_${ID}"

    wrap="$HOME/project"
    runner=$wrap/project_runner
    mkdir -p "$runner"

    output="$runner/project_output_${ID}"
    rm -rf "$output"
    cp -r "$wrap/project_output" "$output"

    tmp_base="${TMPDIR:-/tmp}"
    tmp_input="$tmp_base/project_${FULL_ID}"
    OUTROOT="$tmp_base/$FULL_ID"            # node-local fuzzer output (wiped at job end)
    RESULTS_DIR="$output/results"             # persistent results

    SUT_ORACLE="$output/$ORACLE"
    SUT_TRACE="$output/$TRACE"
    SUT_ARGS=(@@ /dev/null)

    mkdir -p "$tmp_input" "$OUTROOT" "$RESULTS_DIR"
    cp -rf "$wrap/testcases/pdf/." "$tmp_input/"
    SEED_DIR="$tmp_input"

    [ -d "$SEED_DIR" ] || { echo "Missing seed dir: $SEED_DIR" >&2; exit 1; }
    [ -x "$SUT_ORACLE" ] || { echo "Missing oracle: $SUT_ORACLE" >&2; exit 1; }
    [ -x "$SUT_TRACE" ] || { echo "Missing trace: $SUT_TRACE" >&2; exit 1; }

else
    wrap=$(pwd)
    output="$wrap/output"

    ID="local_$(date +%s)_$$"
    FULL_ID="${PROGRAM:-project}_${ID}"

    tmp_base="/tmp"
    tmp_input="$tmp_base/project_${FULL_ID}"
    OUTROOT="$tmp_base/$FULL_ID"
    RESULTS_DIR="$output/results"

    SUT_ORACLE="$output/$ORACLE"
    SUT_TRACE="$output/$TRACE"
    SUT_ARGS=(@@ /dev/null)

    mkdir -p "$tmp_input" "$OUTROOT" "$RESULTS_DIR"
    cp -rf "$wrap/testcases/pdf/." "$tmp_input/"
    SEED_DIR="$tmp_input"

    [ -d "$SEED_DIR" ] || { echo "Missing seed dir: $SEED_DIR" >&2; exit 1; }
    [ -x "$SUT_ORACLE" ] || { echo "Missing oracle: $SUT_ORACLE" >&2; exit 1; }
    [ -x "$SUT_TRACE" ] || { echo "Missing trace: $SUT_TRACE" >&2; exit 1; }
fi

# Assumes one cpu per task
CPU=$(grep Cpus_allowed_list /proc/self/status | awk '{print $2}')

export AFL_DISABLE_TRIM=1
export AFL_FAST_CAL=1                   # fewer calibration runs (3 instead of 4 on stable inputs)
export AFL_NO_SYNC=1                    # don't import other instances' inputs

rc=0
if [[ "${1:-}" = "arc" ]]; then
    ./fuzzer/afl-fuzz -d -i "$SEED_DIR" -o "$OUTROOT" -V "$FUZZ_SECONDS" \
    -t 60 -b "$CPU" -m 1536 -- \
    "$SUT_TRACE" "$SUT_ORACLE" "${SUT_ARGS[@]}" || rc=$?
else
    ./fuzzer/afl-fuzz -d -i "$SEED_DIR" -o "$OUTROOT" -V "$FUZZ_SECONDS" \
    -t 60 -b "$CPU" -m 1536 -- \
    "$SUT_TRACE" "$SUT_ORACLE" "${SUT_ARGS[@]}" || rc=$?
fi
echo "afl-fuzz exited with code $rc"

if [ -f "$OUTROOT/default/fuzzer_stats" ]; then
  cp "$OUTROOT/default/fuzzer_stats" "$RESULTS_DIR/fuzzer_stats_$FULL_ID"
fi

# Tar from the parent so the archive contains only "$FULL_ID/..."
tar -C "$(dirname "$OUTROOT")" -czf "$RESULTS_DIR/$FULL_ID.out.tar.gz" "$FULL_ID"