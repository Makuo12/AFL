#!/bin/bash
#SBATCH --job-name=forkserver_run
#SBATCH --partition=normal_q
#SBATCH --account=fuzzing
#SBATCH --time=25:30:00
#SBATCH --constraint=amd
#SBATCH --nodes=1
#SBATCH --exclusive
#SBATCH --mem=0
#SBATCH --output=./logs/forkserver-%j.log
#SBATCH --error=./logs/forkserver-%j.log
# Add --exclude=<the 8 large-memory node names> here or on the sbatch command line.

# Run from the same directory you used before, because ./fuzzer/afl-fuzz is a relative path.
# Usage: mkdir -p logs && sbatch fuzz_forkserver.sh
#   optional: FUZZ_SECONDS=900 sbatch --time=00:30:00 fuzz_forkserver.sh   (short test)

set -uo pipefail

module load LLVM/20.1.8-GCCcore-14.3.0
module load GCCcore/14.3.0

PROGRAM="forkserver_afl"
ORACLE="main.oracle"
TRACE="main.trace"
NUM_RUNS=10

wrap="$HOME/forkserver/AFL"
runner="$wrap/forkserver_runner"
tmp_base="${TMPDIR:-/tmp}"
FUZZ_SECONDS="${FUZZ_SECONDS:-$((24*60*60))}"
JOB="${SLURM_JOB_ID:-0}"

mkdir -p "$runner" ./logs

echo "node=$(hostname -s) cpu=$(lscpu | grep 'Model name' | sed 's/.*: *//')"

# Make sure we got the standard 128-core, 257712 MB node
REALMEM=$(scontrol show node "$SLURMD_NODENAME" | grep -o 'RealMemory=[0-9]*' | cut -d= -f2)
CORES=$(nproc)
echo "cores=$CORES RealMemory=${REALMEM}MB"
if [ "$REALMEM" != "257712" ] || [ "$CORES" -ne 128 ]; then
    echo "Unexpected node (cores=$CORES, RealMemory=$REALMEM), aborting" >&2
    exit 1
fi
echo "node=$(hostname -s) cores=$CORES RealMemory=${REALMEM}MB job=$JOB" > "$runner/node_${JOB}.txt"

# run_one <run number 1-10> <core>
# Runs as a background subshell, so its exports (LOG_FILE, LOOP_THRESHOLD_FILE, ...) stay private.
run_one() {
    TASK="$1"; CORE="$2"

    export AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1
    export AFL_SKIP_CPUFREQ=1
    export AFL_NO_UI=1
    export AFL_NO_AFFINITY=1          # pinning is done by taskset below
    export AFL_DISABLE_TRIM=1
    export AFL_FAST_CAL=1
    export AFL_NO_SYNC=1

    ID="${JOB}_${TASK}"
    FULL_ID="${PROGRAM}_${ID}"

    output="$runner/output_${ID}"                  # per-run copy
    rm -rf "$output"
    mkdir -p "$output"
    cp -r "$wrap/output/." "$output/"              # binaries, .bc, .ll, edge, remove_edge, ...

    tmp_input="$tmp_base/forkserver_${FULL_ID}"
    OUTROOT="$tmp_base/$FULL_ID"                   # node-local fuzzer output (wiped at job end)
    RESULTS_DIR="$output/results"                  # persistent results
    export LOOP_THRESHOLD_FILE="$OUTROOT/loop_threshold.txt"
    export LOG_FILE="$OUTROOT/fuzzer_log_file"
    SUT_ORACLE="$output/$ORACLE"
    SUT_TRACE="$output/$TRACE"
    SUT_ARGS=(@@ /dev/null)

    mkdir -p "$tmp_input" "$OUTROOT" "$RESULTS_DIR"
    cp -rf "$wrap/testcases/pdf/." "$tmp_input/"

    [ -d "$tmp_input" ] || { echo "Missing seed dir: $tmp_input" >&2; return 1; }
    [ -x "$SUT_ORACLE" ] || { echo "Missing oracle: $SUT_ORACLE" >&2; return 1; }
    [ -x "$SUT_TRACE" ] || { echo "Missing trace: $SUT_TRACE" >&2; return 1; }

    echo "run=$FULL_ID core=$CORE node=$(hostname -s)"

    rc=0
    taskset -c "$CORE" timeout -s INT "$FUZZ_SECONDS" \
        ./fuzzer/afl-fuzz -d -i "$tmp_input" -o "$OUTROOT" \
            -t 5000 -m 2048 -- "$SUT_ORACLE" "${SUT_ARGS[@]}" || rc=$?
    echo "afl-fuzz exited with code $rc"

    [ -f "$OUTROOT/fuzzer_stats" ] && cp "$OUTROOT/fuzzer_stats" "$RESULTS_DIR/fuzzer_stats_$FULL_ID"

    # Tar from the parent so the archive contains only "$FULL_ID/..."
    tar -C "$(dirname "$OUTROOT")" -czf "$RESULTS_DIR/$FULL_ID.out.tar.gz" "$FULL_ID"
}

# Launch all runs, run n on core n (core 0 is left free for the OS)
PIDS=()
for n in $(seq 1 "$NUM_RUNS"); do
    run_one "$n" "$n" > "./logs/${PROGRAM}_${JOB}_${n}.log" 2>&1 &
    PIDS+=($!)
done

# If Slurm stops the job, pass the signal on so each run can save its results
trap 'kill -INT "${PIDS[@]}" 2>/dev/null || true' TERM INT

for p in "${PIDS[@]}"; do wait "$p" || true; done
echo "All runs finished."