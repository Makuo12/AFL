#!/bin/bash
#SBATCH --job-name=single_server_build
#SBATCH --partition=normal_q
#SBATCH --account=fuzzing
#SBATCH --constraint=amd
#SBATCH --time=01:00:00
#SBATCH --ntasks=1
#SBATCH --cpus-per-task=4
#SBATCH --mem-per-cpu=4G
#SBATCH --output=./logs/build-%j.log
#SBATCH --error=./logs/build-%j.log

set -e

if [ "${1:-}" = "arc" ]; then
    module load LLVM/20.1.8-GCCcore-14.3.0
    module load CMake/3.31.8-GCCcore-14.3.0
    module load GCCcore/14.3.0
    pip install --user wllvm
    export PATH="$HOME/.local/bin:$PATH"
    wrap="$HOME/single_server/AFL"
    export BASE_ADDRESS=0x400000
else
    export LLVM_CC_NAME=clang-20        # ← pin to version 20
    export LLVM_CXX_NAME=clang++-20     # ← pin to version 20
    wrap=$(pwd)
    export BASE_ADDRESS=0x400000
fi

echo "Building afl_fuzz"
AFL_NO_X86=1 make -C $wrap/fuzzer afl-fuzz

PERF_FLAGS="-O3 -funroll-loops -DNDEBUG -fno-stack-protector -fomit-frame-pointer -fno-semantic-interposition -fvisibility=hidden"

LIB_PATH="$(llvm-config --libdir)"
BIN_PATH="$(llvm-config --bindir)"
export LLVM_COMPILER=clang

rm -rf $wrap/output
mkdir -p $wrap/output

echo "Building llvm passes"
rm -rf $wrap/build

cmake -B $wrap/build \
      -DLLVM_DIR=$LIB_PATH/cmake/llvm \
      -DCMAKE_BUILD_TYPE=Release 2>&1 | cat
make -C $wrap/build -j$(nproc)


echo "Building utils"

echo "Building xpdf with custom coverage tracer..."
SRC="$wrap/targets/xpdf-4.06_2"
BUILD="$SRC/build"

rm -rf "$BUILD"

COVERAGE_FLAGS="-I $wrap/include -fno-pie"
EXTRA_ARGS=()

case "$(uname -s)" in
  Darwin) ;;
  Linux)  EXTRA_ARGS=(-DCMAKE_EXE_LINKER_FLAGS="-no-pie"
                      -DCMAKE_SHARED_LINKER_FLAGS="-no-pie") ;;
  *) echo "Unknown OS: $(uname -s)"; exit 1 ;;
esac

cmake -S "$SRC" -B "$BUILD" \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_C_COMPILER=wllvm \
  -DCMAKE_CXX_COMPILER=wllvm++ \
  -DCMAKE_TRY_COMPILE_TARGET_TYPE=STATIC_LIBRARY \
  -DCMAKE_C_FLAGS="$COVERAGE_FLAGS" \
  -DCMAKE_CXX_FLAGS="$COVERAGE_FLAGS" \
  "${EXTRA_ARGS[@]}"

cmake --build "$BUILD" -j"$(nproc)"

echo "Extract whole-program bitcode from the final binary"
extract-bc $BUILD/xpdf/pdftotext -o $wrap/output/whole_program.bc

echo "Currently at $(pwd)"
$BIN_PATH/opt \
    -load-pass-plugin=$wrap/build/Untracer.so \
    -passes="rename" \
    $wrap/output/whole_program.bc -o $wrap/output/out.bc

echo "Disassembling bitcode to LLVM IR"
llvm-dis $wrap/output/out.bc -o $wrap/output/out.ll

echo "Make target init"
$BIN_PATH/clang -I $wrap/include -c -emit-llvm $wrap/wrapper/fuzzer.c -o $wrap/output/fuzzer.bc

echo "Building edge-only binary"
$BIN_PATH/clang++ $wrap/src/EdgeCount.cc $wrap/src/EdgeHandler.cc \
    $wrap/src/PCTable.cc $wrap/src/Instrumentation.cc   \
    -I include -o $wrap/output/edge \
    $(llvm-config --cxxflags --ldflags --libs core irreader analysis) \
    $(llvm-config --system-libs) $PERF_FLAGS

$BIN_PATH/clang++ $wrap/src/DeIntrumentation.cc $wrap/src/DeEdgeHandler.cc \
    -I include -o $wrap/output/remove_edge \
    $(llvm-config --cxxflags --ldflags --libs core irreader analysis) \
    $(llvm-config --system-libs) $PERF_FLAGS

$wrap/output/edge "$wrap/output/out.ll" "$wrap/output/main.transformed.ll"

# Fail early if the pass did not tag any globals.
grep -q 'section "__cls_glob"' $wrap/output/main.transformed.ll \
    || { echo "ERROR: pass did not tag any globals"; exit 1; }

# Runtime sources are compiled as C (-x c) so the --wrap symbols and the
# __real_* declarations keep plain C names.
# Runtime sources are compiled as C (-x c) so the --wrap symbols and the
# __real_* declarations keep plain C names.
RUNTIME="-x c $wrap/wrapper/global.c $wrap/wrapper/filer.c $wrap/wrapper/mem_track.c -x none"

# File-handle wrappers (filer.c)
FILE_WRAP_FLAGS="-Wl,--wrap=fopen -Wl,--wrap=fopen64 -Wl,--wrap=freopen -Wl,--wrap=fdopen \
                 -Wl,--wrap=tmpfile -Wl,--wrap=popen -Wl,--wrap=fclose -Wl,--wrap=pclose"

EXIT_WRAP_FLAGS="-Wl,--wrap=exit -Wl,--wrap=_exit -Wl,--wrap=_Exit"

# Heap wrappers (mem_track.c)
MEM_WRAP_FLAGS="-Wl,--wrap=malloc -Wl,--wrap=calloc -Wl,--wrap=realloc -Wl,--wrap=free \
                -Wl,--wrap=reallocarray -Wl,--wrap=memalign -Wl,--wrap=aligned_alloc \
                -Wl,--wrap=posix_memalign -Wl,--wrap=valloc -Wl,--wrap=pvalloc \
                -Wl,--wrap=strdup -Wl,--wrap=strndup \
                -Wl,--wrap=getline -Wl,--wrap=getdelim"

WRAP_FLAGS="$FILE_WRAP_FLAGS $MEM_WRAP_FLAGS $FILE_WRAP_FLAGS"

echo "Building final binary"
if [[ "$(uname -s)" == "Darwin" ]]; then
    INCLUDE="-isysroot $(xcrun --show-sdk-path)"
    $BIN_PATH/clang++  $INCLUDE  \
        $wrap/output/main.transformed.ll $wrap/output/fuzzer.bc \
        -L/opt/homebrew/opt/fontconfig/lib -lfontconfig \
        -o $wrap/output/main.oracle
elif [[ "$(uname -s)" == "Linux" ]]; then
    if [[ "${1:-}" = arc ]]; then
        $BIN_PATH/clang++ $PERF_FLAGS -I $wrap/include \
            $wrap/output/main.transformed.ll $RUNTIME $wrap/output/fuzzer.bc \
            -no-pie -fuse-ld=bfd \
            -Wl,--image-base=$BASE_ADDRESS -Wl,-z,noseparate-code \
            $WRAP_FLAGS \
            -o $wrap/output/main.oracle
    else
        $BIN_PATH/clang++ $PERF_FLAGS -I $wrap/include \
            $wrap/output/main.transformed.ll $RUNTIME $wrap/output/fuzzer.bc \
            -no-pie \
            $WRAP_FLAGS \
            -o $wrap/output/main.oracle
    fi
    cp  $wrap/output/main.oracle $wrap/output/main.trace           # This is just a dummy file to satisfy the fuzzer's expectations. The actual tracing is done by the instrumentation pass.
else
    echo "Unknown OS: $(uname -s)"
    exit 1
fi

echo "Done with build"