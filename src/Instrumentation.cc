#include "common.h"
#include "PCTablePass.h"
#include "Edge.h"
#include <fstream>
#include <map>

using namespace llvm;
using namespace std;

using namespace llvm;

std::vector<std::string> skipFunctions = {
    // runtime / pctable
    "__runtime",
    "pctable",
    "PCTableEntry",
    "__untracer", // also covers __untracer_make_writable, __untracer_restore_global(_sections),
                  // __untracer_setup_global

    // libc / system
    "malloc",
    "realloc",
    "calloc",
    "free",
    "sysconf",
    "sscanf",
    "mprotect",
    "printf",
    "fopen",
    "fclose",
    "fgets",
    "sigemptyset",
    "sigaction",
    "sizeof",

    // uthash
    "HASH_FIND",
    "HASH_ADD",
    "HASH_DEL",
    "HASH_ITER",

    // file-pointer tracking
    "file_ptr_obj",
    "add_file_ptr",
    "find_file_ptr",
    "delete_file_ptr",
    "fopen_hook",
    "fclose_hook",
    "close_open_file_handles",

    // heap-pointer tracking
    "ptr_obj",
    "add_ptr",
    "find_ptr",
    "delete_ptr",
    "myMalloc",
    "myCalloc",
    "myRealloc",
    "myFree",
    "free_ptrs",

    // global-section restore
    "__untracer_make_writable",
    "__untracer_restore_global_sections",
    "__untracer_restore_global",
    "__untracer_setup_global",
};

bool foundInSkipFunctions(StringRef fName)
{
    for (auto func : skipFunctions)
    {
        if (fName.contains(func))
        {
            return true;
        }
    }
    return false;
}

void processBlocks(Module &M, SmallPtrSet<BasicBlock *, 16> &seen)
{
    int wholeCount = 0;
    Type *Int32Ty = Type::getInt32Ty(M.getContext());
    GlobalVariable *TrapIdGV = M.getGlobalVariable("__trap_id");
    if (!TrapIdGV)
    {
        TrapIdGV = new GlobalVariable(
            M, Int32Ty, /*isConstant=*/false,
            GlobalValue::InternalLinkage,
            ConstantInt::get(Int32Ty, 0),
            "__trap_id");
    }
    SmallPtrSet<BasicBlock *, 16> pctableSeen;

    // Create up front so a harness declaring
    // `extern "C" void __reset_loop_counters()` links even with 0 loops.
    getOrCreateResetFn(M);

    // ---- Phase 1: edge handlers, all functions ----
    // These split blocks / edges, so they run BEFORE we count loop headers.
    for (Function &F : M)
    {
        if (!shouldProcessFunction(F))
            continue;
        // handlePCTable(F, M); // not needed for de-instrumentation
        instrumentBlocks(F, seen, wholeCount);
        // for (BasicBlock &BB : llvm::make_early_inc_range(F))
        //     handleDefaultBlockEdge(*BB.getTerminator(), wholeCount, seen);
        // for (BasicBlock &BB : llvm::make_early_inc_range(F))
        //     handleSwitchFallthroughEdge(*BB.getTerminator(), wholeCount, seen);
        for (BasicBlock &BB : llvm::make_early_inc_range(F))
            handleIfEdges(*BB.getTerminator(), wholeCount, seen);
        // for (BasicBlock &BB : llvm::make_early_inc_range(F))
        //     handleInvokeEdges(*BB.getTerminator(), wholeCount, seen);
    }
    // ---- Phase 2: count loop headers, create the array + reset body ----
    // unsigned N = countLoopHeaders(M);
    // GlobalVariable *CounterArr = nullptr;
    // if (N > 0)
    // {
    //     CounterArr = createCounterArray(M, N);
    //     buildResetFn(M, CounterArr, N);
    // }

    // // ---- Phase 3: loop guards, then block instrumentation, per function ----
    // // Same per-function order as before (loops, then instrumentBlocks).
    // unsigned slot = 0;
    // for (Function &F : M)
    // {
    //     if (!shouldProcessFunction(F))
    //         continue;
    //     if (CounterArr)
    //         processLoop(&F, CounterArr, slot, wholeCount);
    //     // Handle PCTable
    // }
    // assert(slot == N && "loop count and loop instrumentation disagree");

    // Call the reset at the top of LLVMFuzzerTestOneInput. Delete this line
    // if you call __reset_loop_counters() from your own harness.
    // insertResetCall(M);

    for (auto bb : pctableSeen)
    {
        bool found = false;
        for (Function &F : M)
        {
            if (bb->getParent() == &F)
                found = true;
        }
        if (!found)
            errs() << "Basic block not found: " << bb << "\n";
    }
}

int writeInfo(map<string, BlockInfo> &blocks)
{
    ofstream file("./output/block_info.txt", std::ios::app);
    if (!file.is_open())
    {
        errs() << "block_info file not open \n";
        return 1;
    }
    string msg;
    for (auto item : blocks)
    {
        msg.clear();
        msg += item.first;
        msg += " Block Count: " + std::to_string(item.second.blockCount);
        msg += " Critical edge Count: " + std::to_string(item.second.criticalEdgeCount);
        msg += "\n";
        file.write(msg.data(), msg.size());
    }
    return 0;
}

void mainCountBlock(Module &M, map<string, BlockInfo> &blocks)
{
    int global_count = 0;
    for (Function &F : M)
    {
        auto search = StringRef("llvm.");
        auto it = std::search(F.getName().begin(), F.getName().end(), search.begin(), search.end());
        if (it != F.getName().end())
            continue; // skip LLVM intrinsics
        if (F.getName() == "main" || foundInSkipFunctions(F.getName()))
        {
            continue;
        }
        processModule(M, F, global_count, blocks);
    }
    writeInfo(blocks);
}

int writeToFile(Module &M, const char *outputFile)
{
    if (verifyModule(M, &errs()))
    {
        errs() << "ERROR: Module is invalid after transform!\n";
        return 1;
    }

    // Write the transformed IR to a new file
    std::error_code EC;
    raw_fd_ostream Out(outputFile, EC);
    if (EC)
    {
        errs() << "Could not open output file: " << EC.message() << "\n";
        return 1;
    }
    M.print(Out, nullptr);
    errs() << "Wrote transformed IR to main.transformed.ll\n";
    return 0;
}

std::unique_ptr<Module> parseFile(const char *filename, SMDiagnostic &Err, LLVMContext &Context)
{
    std::unique_ptr<Module> M = parseIRFile(filename, Err, Context);
    if (!M)
    {
        Err.print(filename, errs());
        return nullptr;
    }
    return M;
}

int main(int argc, char **argv)
{
    map<string, BlockInfo> blocks;
    SmallPtrSet<BasicBlock *, 16> seen;
    if (argc < 2)
    {
        errs() << "Usage: " << argv[0] << " <file.ll>\n";
        return 1;
    }
    const char *inputFile = argv[1];
    const char *outputFile = argv[2];
    LLVMContext Context;
    SMDiagnostic Err;
    auto M = parseFile(inputFile, Err, Context);
    if (M == nullptr)
        return 1;
    // Sanity check the IR is still well-formed after the transform
    // mainCountBlock(*M, blocks);
    // errs() << "Done counting blocks and critical edges.\n";
    processBlocks(*M, seen);
    return writeToFile(*M, outputFile);
}