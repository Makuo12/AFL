#!/bin/bash
#SBATCH --job-name=control_run
#SBATCH --partition=normal_q
#SBATCH --account=fuzzing
#SBATCH --time=25:30:00
#SBATCH --constraint=amd
#SBATCH --nodes=1
#SBATCH --exclusive
#SBATCH --mem=0
#SBATCH --output=./logs/control-%j.log
#SBATCH --error=./logs/control-%j.log

# 15 runs on one exclusive node (3 coverage types x 5 repetitions), one core each.
# Run this from the same directory you used before, because ./fuzzer/afl-fuzz is a relative path.
#
# Usage: mkdir -p logs && sbatch run.slurm

set -uo pipefail

module load LLVM/20.1.8-GCCcore-14.3.0
module load GCCcore/14.3.0

PROGRAM="forkserver_afl"
TYPES=(block edge all)
RUNS_PER_TYPE=5
FUZZ_SECONDS="${FUZZ_SECONDS:-$((24*60*60))}"
JOB="${SLURM_JOB_ID:-0}"

wrap="$HOME/control/AFL"
runner="$wrap/control_runner"
tmp_base="${TMPDIR:-/tmp}"

mkdir -p "$runner" ./logs

echo "node=$(hostname -s) cpu=$(lscpu | grep 'Model name' | sed 's/.*: *//')"
echo "node=$(hostname -s) job=$JOB" > "$runner/node_${JOB}.txt"

# run_one <type: block|edge|all> <repetition 1-5> <core> <task number 1-15>
# Runs as a background subshell, so its exports (COVERAGE_TYPE, LOG_FILE, ...) stay private.
run_one() {
    TYPE="$1"; REP="$2"; CORE="$3"; TASK="$4"

    export AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1
    export AFL_SKIP_CPUFREQ=1
    export AFL_NO_UI=1
    export AFL_NO_AFFINITY=1          # pinning is done by taskset below
    export AFL_DISABLE_TRIM=1
    export AFL_FAST_CAL=1
    export AFL_NO_SYNC=1

    case "$TYPE" in
        block) export COVERAGE_TYPE=BLOCK_COVERAGE; SUT_ARGS=(@@ block /dev/null) ;;
        edge)  export COVERAGE_TYPE=EDGE_COVERAGE;  SUT_ARGS=(@@ edge  /dev/null) ;;
        all)   export COVERAGE_TYPE=ALL_COVERAGE;   SUT_ARGS=(@@ all   /dev/null) ;;
        *) echo "Unknown coverage type: $TYPE" >&2; return 1 ;;
    esac

    ID="${JOB}_${TASK}"               # same naming as the old array: <jobid>_<task 1-15>
    FULL_ID="${PROGRAM}_${TYPE}_run${REP}_${ID}"
    SUT_NAME="main.$TYPE"
    echo "run=$FULL_ID type=$TYPE ($COVERAGE_TYPE) rep=$REP core=$CORE node=$(hostname -s)"

    output="$runner/output_${TYPE}_run${REP}_${ID}"
    rm -rf "$output"
    mkdir -p "$output"
    cp -r "$wrap/output/." "$output/"          # binaries, .bc, .ll, edge, remove_edge, ...

    tmp_input="$tmp_base/control_${FULL_ID}"
    OUTROOT="$tmp_base/$FULL_ID"
    RESULTS_DIR="$output/results"
    export LOOP_THRESHOLD_FILE="$OUTROOT/loop_threshold.txt"
    export LOG_FILE="$OUTROOT/fuzzer_log_file"
    SUT="$output/$SUT_NAME"

    mkdir -p "$tmp_input" "$OUTROOT" "$RESULTS_DIR"
    cp -rf "$wrap/testcases/pdf/." "$tmp_input/"

    [ -d "$tmp_input" ] || { echo "Missing seed dir: $tmp_input" >&2; return 1; }
    [ -x "$SUT" ] || { echo "Missing binary: $SUT" >&2; return 1; }

    rc=0
    taskset -c "$CORE" timeout -s INT "$FUZZ_SECONDS" \
        ./fuzzer/afl-fuzz -d -i "$tmp_input" -o "$OUTROOT" \
            -t 5000 -m 2048 -- "$SUT" "${SUT_ARGS[@]}" || rc=$?
    echo "afl-fuzz exited with code $rc"

    [ -f "$OUTROOT/fuzzer_stats" ] && cp "$OUTROOT/fuzzer_stats" "$RESULTS_DIR/fuzzer_stats_$FULL_ID"

    # Tar from the parent so the archive contains only "$FULL_ID/..."
    tar -C "$(dirname "$OUTROOT")" -czf "$RESULTS_DIR/$FULL_ID.out.tar.gz" "$FULL_ID"
}

# Launch all 15. Cores 1-15, with the three types interleaved (block, edge, all, block, ...)
# so no type systematically gets neighbouring cores. Core 0 is left free for the OS.
PIDS=()
TASK=0
for rep in $(seq 1 $RUNS_PER_TYPE); do
    for t in 0 1 2; do
        TASK=$(( (t * RUNS_PER_TYPE) + rep ))      # block 1-5, edge 6-10, all 11-15, as before
        CORE=$(( (rep - 1) * 3 + t + 1 ))
        run_one "${TYPES[$t]}" "$rep" "$CORE" "$TASK" \
            > "./logs/control_${TYPES[$t]}_run${rep}_${JOB}_${TASK}.log" 2>&1 &
        PIDS+=($!)
    done
done

trap 'kill -INT "${PIDS[@]}" 2>/dev/null || true' TERM INT

for p in "${PIDS[@]}"; do wait "$p" || true; done
echo "All runs finished."