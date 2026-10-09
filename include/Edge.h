#pragma once
#include "common.h"
#include <map>
#include <string>
using namespace llvm;
struct BlockInfo {
    int blockCount = 0;
    int criticalEdgeCount = 0;
};

void handleSwitchFallthroughEdge(Instruction &TI, int &phiNodesInserted, SmallPtrSet<BasicBlock *, 16> &seen);
void handleDefaultBlockEdge(Instruction &TI, int &defaultAddedCount, SmallPtrSet<BasicBlock *, 16> &seen);
void handleInvokeEdges(Instruction &TI, int &invokeAddedCount, SmallPtrSet<BasicBlock *, 16> &seen);
void handleIfEdges(Instruction &TI, int &count, SmallPtrSet<BasicBlock *, 16> &seen);
void handlePCTable(Function &F, Module &M);
void processModule(Module &M, Function &F, int &globalCount, std::map<std::string, BlockInfo> &blocks);
void countCriticalEdge(Instruction &TI, int &globalCount, int &criticalEdgeCount);
void insertCounterGuard(BasicBlock *HeaderBB, GlobalVariable *CounterGV, int &count);
bool foundInSkipFunctions(StringRef fName);
Function *getOrCreateResetFn(Module &M);
bool processLoop(Function *F, GlobalVariable *CounterArr, unsigned &slot, int &count);
bool shouldProcessFunction(Function &F);
unsigned countLoopHeaders(Module &M);
GlobalVariable *createCounterArray(Module &M, unsigned N);
void buildResetFn(Module &M, GlobalVariable *Arr, unsigned N);