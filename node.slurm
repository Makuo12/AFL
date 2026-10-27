#!/bin/bash
#SBATCH --job-name=control_run
#SBATCH --partition=normal_q
#SBATCH --account=fuzzing
#SBATCH --time=25:30:00
#SBATCH --constraint=amd
#SBATCH --ntasks=1
#SBATCH --cpus-per-task=1
#SBATCH --mem-per-cpu=4G
#SBATCH --output=./logs/fuzz-%A_%a.log
#SBATCH --error=./logs/fuzz-%A_%a.log
#SBATCH --array=1-15

# Array layout (15 tasks = 3 coverage types x 5 repetitions):
#   tasks  1-5  -> block
#   tasks  6-10 -> edge
#   tasks 11-15 -> all
#
# Usage:
#   sbatch run.slurm arc            # on the cluster
#   bash run.slurm local [type]     # local run, type = block|edge|all (default: block)

set -euo pipefail

echo "node=$(hostname -s) cpu=$(lscpu | grep 'Model name' | sed 's/.*: *//')"

export AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1
export AFL_SKIP_CPUFREQ=1
export AFL_NO_UI=1
# export AFL_NO_FORKSRV=1
export AFL_NO_AFFINITY=1

export AFL_DISABLE_TRIM=1
export AFL_FAST_CAL=1                   # fewer calibration runs
export AFL_NO_SYNC=1                    # don't import other instances' inputs

FUZZ_SECONDS=$((24*60*60))
PROGRAM="forkserver_afl"

TYPES=(block edge all)
RUNS_PER_TYPE=5

# ---- Map array task -> (coverage type, repetition) ----
if [[ "${1:-}" = "arc" ]]; then
    IDX=$(( ${SLURM_ARRAY_TASK_ID:-1} - 1 ))
    TYPE="${TYPES[$(( IDX / RUNS_PER_TYPE ))]}"
    REP=$(( IDX % RUNS_PER_TYPE + 1 ))
else
    TYPE="${2:-block}"
    REP=1
fi

case "$TYPE" in
    block) 
    export COVERAGE_TYPE=BLOCK_COVERAGE 
    SUT_ARGS=(@@ block /dev/null)
    ;;
    edge)  
    export COVERAGE_TYPE=EDGE_COVERAGE 
    SUT_ARGS=(@@ edge /dev/null)
    ;;
    all)   
    export COVERAGE_TYPE=ALL_COVERAGE 
    SUT_ARGS=(@@ all /dev/null)
    ;;
    *) echo "Unknown coverage type: $TYPE" >&2; exit 1 ;;
esac

SUT_NAME="main.$TYPE"
echo "Coverage type: $TYPE ($COVERAGE_TYPE), repetition $REP/$RUNS_PER_TYPE, binary: $SUT_NAME"

if [[ "${1:-}" = "arc" ]]; then
    module load LLVM/20.1.8-GCCcore-14.3.0
    module load GCCcore/14.3.0
    ID="${SLURM_ARRAY_JOB_ID:-${SLURM_JOB_ID:-0}}_${SLURM_ARRAY_TASK_ID:-0}"
    FULL_ID="${PROGRAM}_${TYPE}_run${REP}_${ID}"

    wrap="$HOME/control/AFL"      # same as build
    runner="$wrap/control_runner"
    mkdir -p "$runner"

    output="$runner/output_${TYPE}_run${REP}_${ID}"   # per-task copy
    rm -rf "$output"
    mkdir -p "$output"
    cp -r "$wrap/output/." "$output/"      # binaries, .bc, .ll, edge, remove_edge, ...

    tmp_base="${TMPDIR:-/tmp}"
    tmp_input="$tmp_base/control_${FULL_ID}"
    OUTROOT="$tmp_base/$FULL_ID"            # node-local fuzzer output (wiped at job end)
    RESULTS_DIR="$output/results"           # persistent results
    export LOOP_THRESHOLD_FILE="$OUTROOT/loop_threshold.txt"
    SUT="$output/$SUT_NAME"
    export LOG_FILE="$OUTROOT/fuzzer_log_file"
    mkdir -p "$tmp_input" "$OUTROOT" "$RESULTS_DIR"
    cp -rf "$wrap/testcases/pdf/." "$tmp_input/"
    SEED_DIR="$tmp_input"
else
    # run on my local linux machine
    wrap=$(pwd)

    ID="local_$(date +%s)_$$"
    FULL_ID="${PROGRAM}_${TYPE}_run${REP}_${ID}"

    output="$wrap/output_${TYPE}_$ID"
    mkdir -p "$output"
    cp -r "$wrap/output/." "$output/"

    tmp_base="/tmp"
    tmp_input="$tmp_base/control_${FULL_ID}"
    OUTROOT="$tmp_base/$FULL_ID"
    RESULTS_DIR="$output/results"

    SUT="$output/$SUT_NAME"

    mkdir -p "$tmp_input" "$OUTROOT" "$RESULTS_DIR"
    cp -rf "$wrap/testcases/pdf/." "$tmp_input/"
    SEED_DIR="$tmp_input"
    export LOOP_THRESHOLD_FILE="$output/loop_threshold.txt"
fi

[ -d "$SEED_DIR" ] || { echo "Missing seed dir: $SEED_DIR" >&2; exit 1; }
[ -x "$SUT" ] || { echo "Missing binary: $SUT" >&2; exit 1; }

rc=0
timeout -s INT "$FUZZ_SECONDS" ./fuzzer/afl-fuzz -d -i "$SEED_DIR" -o "$OUTROOT" \
    -t 5000 -m 2048 -- "$SUT" "${SUT_ARGS[@]}" || rc=$?
echo "afl-fuzz exited with code $rc"

if [ -f "$OUTROOT/fuzzer_stats" ]; then
    cp "$OUTROOT/fuzzer_stats" "$RESULTS_DIR/fuzzer_stats_$FULL_ID"
fi

# Tar from the parent so the archive contains only "$FULL_ID/..."
tar -C "$(dirname "$OUTROOT")" -czf "$RESULTS_DIR/$FULL_ID.out.tar.gz" "$FULL_ID"
