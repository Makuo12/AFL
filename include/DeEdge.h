#pragma once
#include "common.h"
#include <map>
#include <string>
using namespace llvm;

void neutralizeBlock(CallInst *Trap);
bool isNeutralized(BasicBlock *BB);
void collapseFallthroughSite(BasicBlock *CaseBB, SmallVectorImpl<PHINode *> &preservedEntryPhis);