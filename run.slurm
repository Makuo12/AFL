#!/bin/bash
#SBATCH --job-name=de_forkserver_run
#SBATCH --partition=normal_q
#SBATCH --account=fuzzing
#SBATCH --time=25:30:00
#SBATCH --constraint=amd
#SBATCH --ntasks=1
#SBATCH --cpus-per-task=1
#SBATCH --mem-per-cpu=8G
#SBATCH --output=./logs/fuzz-%j.log
#SBATCH --error=./logs/fuzz-%j.log
#SBATCH --array=1-3

set -euo pipefail

echo "node=$(hostname -s) cpu=$(lscpu | grep 'Model name' | sed 's/.*: *//')"

export AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1
export AFL_SKIP_CPUFREQ=1
export AFL_NO_UI=1
# export AFL_NO_FORKSRV=1  
export AFL_NO_AFFINITY=1

export AFL_DISABLE_TRIM=1
export AFL_FAST_CAL=1                   # fewer calibration runs (3 instead of 4 on stable inputs)
export AFL_NO_SYNC=1                    # don't import other instances' inputs

FUZZ_SECONDS=$((2*60*60))
TRACE="main.trace"
PROGRAM="de_forkserver_afl"


if [[ "${1:-}" = "arc" ]]; then
module load LLVM/20.1.8-GCCcore-14.3.0
    module load GCCcore/14.3.0
    ID="${SLURM_ARRAY_JOB_ID:-${SLURM_JOB_ID:-0}}_${SLURM_ARRAY_TASK_ID:-0}"
    FULL_ID="${PROGRAM}_${ID}"

    wrap="$HOME/de_forkserver/AFL"      # same as build
    runner="$wrap/de_forkserver_runner"
    mkdir -p "$runner"

    output="$runner/output_${ID}"                # per-task copy
    rm -rf "$output"
    mkdir -p "$output"
    cp -r "$wrap/output/." "$output/"      # everything: binaries, .bc, .ll, edge, remove_edge, ...

    tmp_base="${TMPDIR:-/tmp}"
    tmpfs_base="${TMPFS:-/tmp}"

    tmp_input="$tmp_base/de_forkserver_${FULL_ID}"
    OUTROOT="$tmp_base/$FULL_ID"            # node-local fuzzer output (wiped at job end)
    RESULTS_DIR="$output/results"             # persistent results
    FASTROOT="$tmpfs_base/${FULL_ID}_fast"

    mkdir -p "$tmp_input" "$OUTROOT" "$RESULTS_DIR" "$FASTROOT"

    export LOG_FILE="$OUTROOT/fuzzer_log_file"
    export LOOP_THRESHOLD_FILE="$FASTROOT/fuzzer_loop_threshold.txt"
    export META_DATA_FILE="$FASTROOT/fuzzer_meta_data.txt"
    export OUTPUT_HOME="$output"
    export DE_EDGE_MAX=2000 # new edges + loop buckets before we de-instrument
    export DE_EDGE_ARC=1    # relink with bfd + image-base like build.slurm
    : > "$META_DATA_FILE"; : > "$LOOP_THRESHOLD_FILE"

    cp -rf "$wrap/testcases/pdf/." "$tmp_input/"
    SUT_TRACE="$output/$TRACE"
    SUT_ARGS=(@@ /dev/null)
    SEED_DIR="$tmp_input"

    [ -d "$SEED_DIR" ] || { echo "Missing seed dir: $SEED_DIR" >&2; exit 1; }
    [ -x "$SUT_TRACE" ] || { echo "Missing trace: $SUT_TRACE" >&2; exit 1; }

else
    # run on my local linux machine
    wrap=$(pwd)

    ID="local_$(date +%s)_$$"
    FULL_ID="${PROGRAM:-de_forkserver}_${ID}"

    output="$wrap/output_$ID"
    mkdir -p "$output"
    cp -r "$wrap/output/." "$output/"

    tmp_base="/tmp"
    tmp_input="$tmp_base/de_forkserver_${FULL_ID}"
    OUTROOT="$tmp_base/$FULL_ID"
    RESULTS_DIR="$output/results"

    SUT_TRACE="$output/$TRACE"
    SUT_ARGS=(@@ /dev/null)



    mkdir -p "$tmp_input" "$OUTROOT" "$RESULTS_DIR"
    cp -rf "$wrap/testcases/pdf/." "$tmp_input/"
    SEED_DIR="$tmp_input"

    export OUTPUT_HOME="$output"
    export META_DATA_FILE="$output/fuzzer_meta_data.txt"
    export LOOP_THRESHOLD_FILE="$output/fuzzer_loop_threshold.txt"
    export DE_EDGE_MAX=3000
    export LOG_FILE="$OUTROOT/fuzzer_log_file"
    : > "$META_DATA_FILE"; : > "$LOOP_THRESHOLD_FILE"

    [ -d "$SEED_DIR" ] || { echo "Missing seed dir: $SEED_DIR" >&2; exit 1; }
    [ -x "$SUT_TRACE" ] || { echo "Missing trace: $SUT_TRACE" >&2; exit 1; }
fi

rc=0
if [[ "${1:-}" = "arc" ]]; then
    timeout -s INT "$FUZZ_SECONDS" ./fuzzer/afl-fuzz -d -i "$SEED_DIR" -o "$OUTROOT" \
    -t 5000 -m 4096 -- "$SUT_TRACE" "${SUT_ARGS[@]}" || rc=$?
else
    timeout -s INT "$FUZZ_SECONDS" ./fuzzer/afl-fuzz -d -i "$SEED_DIR" -o "$OUTROOT" \
    -t 5000 -m 4096 -- "$SUT_TRACE" "${SUT_ARGS[@]}" || rc=$?
fi
echo "afl-fuzz exited with code $rc"

if [ -f "$OUTROOT/fuzzer_stats" ]; then
  cp "$OUTROOT/fuzzer_stats" "$RESULTS_DIR/fuzzer_stats_$FULL_ID"
fi

# Tar from the parent so the archive contains only "$FULL_ID/..."
tar -C "$(dirname "$OUTROOT")" -czf "$RESULTS_DIR/$FULL_ID.out.tar.gz" "$FULL_ID"