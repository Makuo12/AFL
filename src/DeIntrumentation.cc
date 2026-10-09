#include "DeEdge.h"
#include <getopt.h>
#include <fstream>
#include <unordered_set>
#include <memory>

using namespace std;
using namespace llvm;

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

void removeSwitchFallthroughInstrumentation(unordered_set<int32_t> &metaIds, std::vector<CallInst *> &traps)
{
    SmallPtrSet<BasicBlock *, 16> toCheck;
    for (CallInst *Trap : traps)
    {
        if (!Trap->getParent())
        {
            errs() << "[deinstr] ERROR: fallthrough trap instruction is no longer attached "
                      "to a basic block; skipping\n";
            continue;
        }
        BasicBlock *BB = Trap->getParent();
        BasicBlock *CaseBB = BB->getUniquePredecessor();

        if (!CaseBB)
        {
            errs() << "[deinstr] ERROR: block '" << BB->getName()
                   << "' has no unique predecessor - not touching it\n";
            assert(false && "trap/direct block must have exactly one predecessor "
                            "(the CaseBB with the conditional branch)");
            continue;
        }

        neutralizeBlock(Trap);

        if (!isNeutralized(BB))
        {
            errs() << "[deinstr] ERROR: '" << BB->getName()
                   << "' failed to neutralize (postcondition failed)\n";
            assert(false && "neutralizeBlock postcondition failed: "
                            "block is not a single unconditional br");
        }

        toCheck.insert(CaseBB);
    }

    SmallVector<PHINode *, 8> preservedEntryPhis;
    for (BasicBlock *CaseBB : toCheck)
    {
        auto *CondBr = dyn_cast_or_null<BranchInst>(CaseBB->getTerminator());
        if (!CondBr || !CondBr->isConditional())
            continue; // already collapsed, or unexpected shape - not an error

        BasicBlock *TrapBB = CondBr->getSuccessor(0);
        BasicBlock *DirectBB = CondBr->getSuccessor(1);

        if (isNeutralized(TrapBB) && isNeutralized(DirectBB))
            collapseFallthroughSite(CaseBB, preservedEntryPhis);
    }

    // Fixpoint sweep: a preserved .entry PHI can lose its last user later
    // in this same pass (its downstream consumer got collapsed too), which
    // can in turn free up something further upstream.
    bool changed = true;
    while (changed)
    {
        changed = false;
        for (auto it = preservedEntryPhis.begin(); it != preservedEntryPhis.end();)
        {
            if ((*it)->use_empty())
            {
                (*it)->eraseFromParent();
                it = preservedEntryPhis.erase(it);
                changed = true;
            }
            else
                ++it;
        }
    }

    // Final sanity check: catch any dangling-use / dominance breakage from
    // this pass immediately, with a clear culprit, instead of surfacing as
    // a confusing crash three passes later.
    // std::string errMsg;
    // raw_string_ostream OS(errMsg);
    // if (verifyFunction(F, &OS))
    // {
    //     errs() << "[deinstr] FUNCTION VERIFICATION FAILED after deinstrumenting '"
    //            << F.getName() << "':\n"
    //            << OS.str();
    //     assert(false && "removeSwitchFallthroughInstrumentation produced invalid IR");
    // }
}

void removeDefaultBlockInstrumentation(unordered_set<int32_t> &metaIds, std::vector<CallInst *> &traps)
{
    for (CallInst *Trap : traps)
    {
        if (!Trap->getParent())
        {
            errs() << "[deinstr] ERROR: Default block trap instruction is no longer attached "
                      "to a basic block; skipping\n";
            continue;
        }
        BasicBlock *NewDefaultBB = Trap->getParent();
        BasicBlock *Pred = NewDefaultBB->getUniquePredecessor();
        BasicBlock *Succ = NewDefaultBB->getUniqueSuccessor();
        if (!Pred || !Succ)
        {
            errs() << "[deinstr] ERROR: default block '" << NewDefaultBB->getName()
                   << "' is not self-contained (missing unique pred/succ)\n";
            assert(false && "expected a self-contained sw.default.dedicated block");
            continue;
        }

        Instruction *PredTI = Pred->getTerminator();
        for (unsigned i = 0, e = PredTI->getNumSuccessors(); i != e; ++i)
        {
            if (PredTI->getSuccessor(i) == NewDefaultBB)
                PredTI->setSuccessor(i, Succ);
        }

        for (PHINode &PN : Succ->phis())
        {
            int idx = PN.getBasicBlockIndex(NewDefaultBB);
            if (idx >= 0)
                PN.setIncomingBlock(idx, Pred);
        }

        NewDefaultBB->eraseFromParent();
    }
}

void removeBlockInstrumentation(unordered_set<int32_t> &metaIds, std::vector<CallInst *> &traps)
{
    for (CallInst *Trap : traps)
    {
        if (!Trap->use_empty())
        {
            errs() << "[deinstr] ERROR: block trap call result in '"
                   << Trap->getParent()->getName()
                   << "' has unexpected uses\n";
            assert(false && "unexpected use of block trap call result");
            continue;
        }
        // No CFG changes needed: the trap is just an ordinary instruction
        // sitting before the block's real first instruction. Erasing it
        // leaves the block's control flow, PHIs, and everything else
        // completely untouched.
        Trap->eraseFromParent();
    }
}

void findTrapInstructions(
    Module &M, unordered_set<int32_t> &metaIds,
    unordered_map<int32_t, int32_t> &thresholds,
    std::vector<CallInst *> &elseArmTraps,
    std::vector<CallInst *> &defaultSwitchTraps,
    std::vector<CallInst *> &fellthroughSwitchTraps,
    std::vector<CallInst *> &invokeTraps,
    std::vector<CallInst *> &loopCountTraps,
    std::vector<CallInst *> &blockTraps,
    std::vector<CallInst *> &allLoopCountTraps)
{
    // Estimate upper bound based on instruction count to avoid dynamic reallocations
    set<int64_t> inIds;
    set <int64_t> loopIds;
    for (Function &F : M)
    {
        for (Instruction &I : instructions(F))
        {
            if (auto *CI = dyn_cast<CallInst>(&I))
            {
                if (MDNode *MD = CI->getMetadata("else_block_id"))
                {
                    int64_t id = mdconst::extract<ConstantInt>(MD->getOperand(0))->getSExtValue();
                    inIds.insert(id);
                    if (metaIds.find(id) != metaIds.end())
                        elseArmTraps.emplace_back(CI);
                }
                else if (MDNode *MD = CI->getMetadata("invoke_block_id"))
                {
                    int64_t id = mdconst::extract<ConstantInt>(MD->getOperand(0))->getSExtValue();
                    inIds.insert(id);
                    if (metaIds.find(id) != metaIds.end())
                        invokeTraps.emplace_back(CI);
                }
                else if (MDNode *MD = CI->getMetadata("switch_fallthrough_id"))
                {
                    int64_t id = mdconst::extract<ConstantInt>(MD->getOperand(0))->getSExtValue();
                    inIds.insert(id);
                    if (metaIds.find(id) != metaIds.end())
                        fellthroughSwitchTraps.emplace_back(CI);
                }
                else if (MDNode *MD = CI->getMetadata("default_block_id"))
                {
                    int64_t id = mdconst::extract<ConstantInt>(MD->getOperand(0))->getSExtValue();
                    inIds.insert(id);
                    if (metaIds.find(id) != metaIds.end())
                        defaultSwitchTraps.emplace_back(CI);
                }
                else if (MDNode *MD = CI->getMetadata("loop_header_id"))
                {
                    int64_t id = mdconst::extract<ConstantInt>(MD->getOperand(0))->getSExtValue();
                    inIds.insert(id);
                    loopIds.insert(id);
                    // Unconditionally record EVERY loop trap here, regardless
                    // of metaIds membership, so applyLoopThresholds() below
                    // can find and patch the ones that are still active
                    // (i.e. NOT in metaIds -- those get fully removed instead
                    // by removeLoopInstrumentation).
                    if (thresholds.find(id) != thresholds.end()) {
                        allLoopCountTraps.emplace_back(CI);
                    }
                    if (metaIds.find(id) != metaIds.end())
                        loopCountTraps.emplace_back(CI);
                }
                else if (MDNode *MD = CI->getMetadata("block_id"))
                {
                    int64_t id = mdconst::extract<ConstantInt>(MD->getOperand(0))->getSExtValue();
                    inIds.insert(id);
                    if (metaIds.find(id) != metaIds.end())
                        blockTraps.emplace_back(CI);
                }
            }
        }
    }
    // errs() << "meta_id not found: ";
    // for (int32_t id: metaIds) {
    //     if (inIds.find(id) == inIds.end()) {
    //         errs() << id << ", ";
    //     }
    // }
    // errs() << ",\n";
    // errs() << "thresholds: ";
    // for (auto item: thresholds) {
    //     errs() << item.first << ", ";
    //     if (inIds.find(item.first) == inIds.end()) {
    //         errs() << "loop_ids special not found: " << item.first << "\n";
    //     }
    // }
    // errs() << ",\n";
    // for (auto item: thresholds) {
    //     if (loopIds.find(item.first) == loopIds.end()) {
    //         errs() << "loop_count special not found: " << item.first << "\n";
    //     }
    // }

}

void removeIfEdgeInstrumentation(unordered_set<int32_t> &metaIds, std::vector<CallInst *> &traps)
{
    for (CallInst *Trap : traps)
    {
        if (!Trap->getParent())
        {
            errs() << "[deinstr] ERROR: If-else arm trap instruction is no longer attached "
                      "to a basic block; skipping\n";
            continue;
        }
        BasicBlock *NewElseBB = Trap->getParent();

        BasicBlock *Pred = NewElseBB->getUniquePredecessor();
        BasicBlock *Succ = NewElseBB->getUniqueSuccessor();
        if (!Pred || !Succ)
        {
            errs() << "[deinstr] ERROR: else block '" << NewElseBB->getName()
                   << "' is not self-contained (missing unique pred/succ)\n";
            assert(false && "expected a self-contained if.else.new block");
            continue;
        }

        Instruction *PredTI = Pred->getTerminator();
        for (unsigned i = 0, e = PredTI->getNumSuccessors(); i != e; ++i)
        {
            if (PredTI->getSuccessor(i) == NewElseBB)
                PredTI->setSuccessor(i, Succ);
        }

        for (PHINode &PN : Succ->phis())
        {
            int idx = PN.getBasicBlockIndex(NewElseBB);
            if (idx >= 0)
                PN.setIncomingBlock(idx, Pred);
        }

        NewElseBB->eraseFromParent();
    }
}

void removeInvokeInstrumentation(unordered_set<int32_t> &metaIds, std::vector<CallInst *> &traps)
{
    for (CallInst *Trap : traps)
    {
        if (!Trap->getParent())
        {
            errs() << "[deinstr] ERROR: invoke trap instruction is no longer attached "
                      "to a basic block; skipping\n";
            continue;
        }
        BasicBlock *BB = Trap->getParent();

        if (!Trap->use_empty())
        {
            errs() << "[deinstr] ERROR: trap call result in '" << BB->getName()
                   << "' has unexpected uses\n";
            assert(false && "unexpected use of trap call result");
            continue;
        }

        BasicBlock *Pred = BB->getUniquePredecessor();
        BasicBlock *Succ = BB->getUniqueSuccessor();
        bool isSplicedBlock = false;
        if (Pred && Succ)
        {
            unsigned nonPhiCount = 0;
            for (Instruction &I : *BB)
            {
                if (isa<PHINode>(I))
                    continue;
                ++nonPhiCount;
            }
            // A block created solely to host the trap contains just the
            // call and its unconditional branch to the real successor.
            if (nonPhiCount == 2) // call, br
                isSplicedBlock = true;
        }

        if (isSplicedBlock)
        {
            Instruction *PredTI = Pred->getTerminator();
            for (unsigned i = 0, e = PredTI->getNumSuccessors(); i != e; ++i)
            {
                if (PredTI->getSuccessor(i) == BB)
                    PredTI->setSuccessor(i, Succ);
            }
            for (PHINode &PN : Succ->phis())
            {
                int idx = PN.getBasicBlockIndex(BB);
                if (idx >= 0)
                    PN.setIncomingBlock(idx, Pred);
            }
            BB->eraseFromParent();
        }
        else
        {
            // In-place case: just remove the trap call, leaving the rest
            // of NormalDest (including any PHIs) untouched.
            Trap->eraseFromParent();
        }
    }
}

// Removes the per-loop counter alloca once its guard call is gone.
// The only remaining users should be the preheader reset store (and,
// defensively, lifetime markers / dead casts). If anything else still
// uses the alloca, nothing is erased and the alloca is left in place.
static void eraseLoopCounterAlloca(AllocaInst *Counter, StringRef FName)
{
    SmallVector<Instruction *, 4> ToErase;
    bool Clean = true;

    for (User *U : Counter->users())
    {
        auto *UI = dyn_cast<Instruction>(U);
        if (!UI)
        {
            Clean = false;
            continue;
        }

        if (auto *SI = dyn_cast<StoreInst>(UI))
        {
            // Only a store *to* the counter (the preheader reset), not
            // one that stores the counter's address somewhere.
            if (SI->getPointerOperand() == Counter &&
                SI->getValueOperand() != Counter)
            {
                ToErase.push_back(SI);
                continue;
            }
        }
        else if (auto *II = dyn_cast<IntrinsicInst>(UI))
        {
            if (II->isLifetimeStartOrEnd())
            {
                ToErase.push_back(II);
                continue;
            }
        }
        else if (isa<CastInst>(UI) && UI->use_empty())
        {
            ToErase.push_back(UI);
            continue;
        }
        Clean = false;
    }

    if (!Clean)
    {
        errs() << "[deinstr] ERROR: counter alloca '" << Counter->getName()
               << "' in function '" << FName
               << "' still has unexpected use(s) after removing its guard "
                  "call — leaving it in the function\n";
        return;
    }

    for (Instruction *I : ToErase)
        I->eraseFromParent();
    Counter->eraseFromParent();
}

// Counters are now slots in the global @loop_counters array, so there is no
// per-loop alloca and no preheader reset store to clean up. The guard call's
// single argument is either:
//   - a `getelementptr inbounds` instruction (&loop_counters[slot]), or
//   - a constant-expression GEP, if IRBuilder constant-folded it (base and
//     indices are all constants, so this is common).
// Only the instruction form needs erasing. The array slot itself stays; it's
// harmless (still zeroed by the memset in __reset_loop_counters).
void removeLoopInstrumentation(unordered_set<int32_t> &metaIds, std::vector<CallInst *> &traps)
{
    for (CallInst *Trap : traps)
    {
        if (!Trap->getParent())
        {
            errs() << "[deinstr] ERROR: loop trap instruction is no longer attached "
                      "to a basic block; skipping\n";
            continue;
        }

        StringRef FName = Trap->getFunction()->getName();

        // Grab the slot pointer before the call is erased.
        GetElementPtrInst *SlotGEP = nullptr;
        if (Trap->arg_size() != 1)
        {
            errs() << "[deinstr] ERROR: loop guard call in function '" << FName
                   << "' has " << Trap->arg_size()
                   << " args, expected 1 — skipping slot cleanup for this call\n";
        }
        else
        {
            // Null for the constant-expression case, which is fine.
            SlotGEP = dyn_cast<GetElementPtrInst>(Trap->getArgOperand(0));
        }

        // The id bytes and the trap live in the same asm blob, so erasing
        // this one call removes both.
        Trap->eraseFromParent();

        // Erase the now-dead GEP, but only if nothing else uses it.
        if (SlotGEP && SlotGEP->use_empty())
            SlotGEP->eraseFromParent();
    }
}
/* ---------------- LOOP THRESHOLD RESTORATION ----------------
 * Companion to removeLoopInstrumentation: instead of erasing a loop's
 * guard call, this rewrites its inline asm so the initial cmp immediate
 * (originally hardcoded to 1 by insertCounterGuard) is replaced with the
 * threshold the fuzzer had already advanced it to before this recompile.
 * Without this, every recompile silently resets every still-active loop
 * counter back to its starting value -- see loop_thresholds.txt for the
 * id -> cmp_value snapshot written by untracer.c just before triggering
 * remove_instrumentation().
 */

void loadThresholds(unordered_map<int32_t, int32_t> &thresholds, string &thresholdFile)
{
    if (thresholdFile.empty())
    {
        return; // no threshold file provided -- nothing to restore, not an error
    }
    ifstream file(thresholdFile);
    if (!file)
    {
        errs() << "[deinstr] WARNING: could not open threshold file '"
               << thresholdFile << "' -- proceeding with no threshold restoration\n";
        return;
    }
    string line;
    int32_t id;
    int32_t cmp_value;
    int lineNo = 0;
    while (getline(file, line))
    {
        ++lineNo;
        if (line.empty())
            continue;
        int parsed = sscanf(line.data(), "%d,%d", &id, &cmp_value);
        if (parsed != 2)
        {
            errs() << "[deinstr] [thresholds] WARNING: malformed line " << lineNo
                   << " ('" << line << "') -- skipping\n";
            continue;
        }
        thresholds[id] = cmp_value;
    }
}

// Rewrites only the imm32 of the forced-imm32 "cmp eax, imm32" inside an
// existing loop-guard asm string:
//     ".byte 0x3d, 0x01, 0x00, 0x00, 0x00\n\t"
//                  ^^^^^^^^^^^^^^^^^^^^^^ these four bytes
// Everything else (id bytes, marker, trap byte, labels) is left untouched.
static bool patchCmpImmediate(std::string &Asm, int32_t newThreshold)
{
    static const std::string Prefix = ".byte 0x3d, ";
    size_t pos = Asm.find(Prefix);
    if (pos == std::string::npos)
        return false;

    size_t start = pos + Prefix.size();
    size_t end = Asm.find('\n', start);
    if (end == std::string::npos)
        return false;

    uint32_t u = static_cast<uint32_t>(newThreshold);
    std::string imm =
        std::to_string(u & 0xFF) + ", " +
        std::to_string((u >> 8) & 0xFF) + ", " +
        std::to_string((u >> 16) & 0xFF) + ", " +
        std::to_string((u >> 24) & 0xFF);

    Asm.replace(start, end - start, imm);
    return true;
}

// InlineAsm objects are uniqued and immutable, so "updating" means building a
// new InlineAsm from the old one's string, then swapping the call.
// Returns the new call (the old one is erased), or nullptr on failure, in
// which case Trap is left untouched and still valid.
CallInst *updateLoopCounterThreshold(CallInst *Trap, int32_t id, int32_t newThreshold)
{
    if (!Trap->getParent())
    {
        errs() << "[deinstr] ERROR: loop trap for id " << id
               << " is no longer attached to a basic block; skipping threshold restore\n";
        return nullptr;
    }
    if (Trap->arg_size() != 1)
    {
        errs() << "[deinstr] ERROR: loop guard call for id " << id << " has "
               << Trap->arg_size() << " args, expected 1 — skipping threshold restore\n";
        return nullptr;
    }

    auto *OldIA = dyn_cast<InlineAsm>(Trap->getCalledOperand());
    if (!OldIA)
    {
        errs() << "[deinstr] ERROR: loop guard call for id " << id
               << " is not an inline asm call — skipping threshold restore\n";
        return nullptr;
    }

    std::string AsmStr = OldIA->getAsmString();
    if (!patchCmpImmediate(AsmStr, newThreshold))
    {
        errs() << "[deinstr] ERROR: could not find cmp immediate in guard asm for id "
               << id << " — skipping threshold restore\n";
        return nullptr;
    }

    // Reuse function type, constraints and flags from the old asm so only
    // the string changes.
    InlineAsm *NewIA = InlineAsm::get(
        OldIA->getFunctionType(), AsmStr, OldIA->getConstraintString(),
        OldIA->hasSideEffects(), OldIA->isAlignStack(),
        OldIA->getDialect(), OldIA->canThrow());

    IRBuilder<> Builder(Trap);
    CallInst *NewCall = Builder.CreateCall(NewIA, {Trap->getArgOperand(0)});
    NewCall->copyMetadata(*Trap); // loop_header_id, debug loc, etc.

    Trap->eraseFromParent(); // void call, no uses to replace
    return NewCall;
}

// Rebuilds a single loop guard's inline asm with a new starting cmp
// immediate, keeping the id encoding, marker bytes, and CounterGV
// argument identical to the original insertCounterGuard-produced call.
void updateLoopCounterThresholdDirect(CallInst *Trap, int32_t id, int32_t newThreshold)
{
    if (!Trap->getParent())
    {
        errs() << "[deinstr] ERROR: loop trap for id " << id
               << " is no longer attached to a basic block; skipping threshold restore\n";
        return;
    }
    if (Trap->arg_size() != 1)
    {
        errs() << "[deinstr] ERROR: loop guard call for id " << id << " has "
               << Trap->arg_size() << " args, expected 1 — skipping threshold restore\n";
        return;
    }

    Value *CounterArg = Trap->getArgOperand(0);
    LLVMContext &Ctx = Trap->getContext();

    uint32_t uthresh = static_cast<uint32_t>(newThreshold);
    unsigned t0 = uthresh & 0xFF;
    unsigned t1 = (uthresh >> 8) & 0xFF;
    unsigned t2 = (uthresh >> 16) & 0xFF;
    unsigned t3 = (uthresh >> 24) & 0xFF;

    // id bytes are re-derived from `id` directly rather than scraped back
    // out of the old asm string, since we're regenerating the whole
    // string from scratch anyway -- this keeps it symmetric with
    // insertCounterGuard's own encoding.
    uint32_t uid = static_cast<uint32_t>(id);
    unsigned b0 = uid & 0xFF;
    unsigned b1 = (uid >> 8) & 0xFF;
    unsigned b2 = (uid >> 16) & 0xFF;
    unsigned b3 = (uid >> 24) & 0xFF;

    std::string AsmStr =
        "movl ($0), %eax\n\t"
        ".byte 0x3d, " +
        std::to_string(t0) + ", " + std::to_string(t1) + ", " +
        std::to_string(t2) + ", " + std::to_string(t3) + "\n\t"
                                                         "jle 1f\n\t"
                                                         ".byte 0xcc\n\t"                   // single trap byte
                                                         ".byte 0x90, 0x90, 0x90, 0x90\n\t" // 4-byte marker distinguishing loop from edge
                                                         ".byte " +
        std::to_string(b0) + ", " + std::to_string(b1) + ", " +
        std::to_string(b2) + ", " + std::to_string(b3) + "\n\t"
                                                         "1:\n\t"
                                                         "addl $$1, %eax\n\t"
                                                         "movl %eax, ($0)\n\t";

    PointerType *I32PtrTy = PointerType::getUnqual(Type::getInt32Ty(Ctx));
    FunctionType *AsmFTy =
        FunctionType::get(Type::getVoidTy(Ctx), {I32PtrTy}, /*isVarArg=*/false);

    InlineAsm *NewIA = InlineAsm::get(
        AsmFTy, AsmStr,
        /*Constraints=*/"r,~{eax},~{cc},~{memory}",
        /*hasSideEffects=*/true);

    IRBuilder<> Builder(Trap);
    CallInst *NewCall = Builder.CreateCall(NewIA, {CounterArg});
    NewCall->setMetadata("loop_header_id", Trap->getMetadata("loop_header_id"));

    Trap->replaceAllUsesWith(NewCall); // safe even though the call is void / has no real uses
    Trap->eraseFromParent();
}

// Driver: for every loop trap NOT being retired this round (id absent from
// metaIds), restore its persisted threshold if it has one.
void applyLoopThresholds(unordered_map<int32_t, int32_t> &thresholds,
                         unordered_set<int32_t> &metaIds,
                         std::vector<CallInst *> &allLoopCountTraps)
{
    // Iterate by reference: the old CallInst is erased on success, so the
    // vector entry must be repointed at the replacement or it dangles.
    for (CallInst *&CI : allLoopCountTraps)
    {
        MDNode *MD = CI->getMetadata("loop_header_id");
        if (!MD)
            continue;
        int32_t id = (int32_t)mdconst::extract<ConstantInt>(MD->getOperand(0))->getSExtValue();

        if (metaIds.find(id) != metaIds.end())
            continue; // retiring this round -- removeLoopInstrumentation handles it

        auto it = thresholds.find(id);
        if (it == thresholds.end())
            continue; // never advanced past its starting threshold
        // updateLoopCounterThresholdDirect(CI, id, it->second);
        if (CallInst *NewCall = updateLoopCounterThreshold(CI, id, it->second))
            CI = NewCall;
    }
}
/* -------------- END LOOP THRESHOLD RESTORATION -------------- */

void loadData(unordered_set<int32_t> &metaIds, string &metaFile)
{
    ifstream file(metaFile);
    if (!file)
    {
        errs() << "[deinstr] ERROR: could not open meta file '" << metaFile << "'\n";
        return;
    }
    string line;
    while (getline(file, line))
    {
        int32_t value = std::atoi(line.data());
        metaIds.insert(value);
    }
}

int writeToFile(Module &M, const char *outputFile)
{
    if (verifyModule(M, &errs()))
    {
        errs() << "ERROR: Module is invalid after transform!\n";
        return 1;
    }

    std::error_code EC;
    raw_fd_ostream Out(outputFile, EC);
    if (EC)
    {
        errs() << "Could not open output file: " << EC.message() << "\n";
        return 1;
    }
    M.print(Out, nullptr);
    return 0;
}

int main(int argc, char **argv)
{
    int c;
    string metaFile;
    string inputFile;
    string outputFile;
    string thresholdFile; // NEW: optional -l <loop_thresholds.txt>
    while ((c = getopt(argc, argv, "m:i:o:l:")) > 0)
    {
        switch (c)
        {
        case 'i':
            inputFile = optarg;
            break;
        case 'm':
            metaFile = optarg;
            break;
        case 'o':
            outputFile = optarg;
            break;
        case 'l':
            thresholdFile = optarg;
            break;
        default:
            exit(EXIT_FAILURE);
        }
    }
    if (metaFile.empty() || inputFile.empty())
    {
        errs() << "Usage: " << argv[0]
               << " -i <file.ll> -m <meta_data.txt> -o <output_file> [-l <loop_thresholds.txt>]\n";
        return 1;
    }
    LLVMContext Context;
    SMDiagnostic Err;
    auto M = parseFile(inputFile.data(), Err, Context);
    if (M == nullptr)
        return 1;
    unordered_set<int32_t> metaIds;
    loadData(metaIds, metaFile);
    unordered_map<int32_t, int32_t> thresholds;
    loadThresholds(thresholds, thresholdFile);
    std::vector<CallInst *> elseArmTraps;
    std::vector<CallInst *> defaultSwitchTraps;
    std::vector<CallInst *> fellthroughSwitchTraps;
    std::vector<CallInst *> invokeTraps;
    std::vector<CallInst *> loopCountTraps;
    std::vector<CallInst *> blockTraps;
    std::vector<CallInst *> allLoopCountTraps;
    findTrapInstructions(*M, metaIds, thresholds, elseArmTraps, defaultSwitchTraps, fellthroughSwitchTraps, invokeTraps, loopCountTraps, blockTraps, allLoopCountTraps);
    if (!thresholds.empty()) {
        applyLoopThresholds(thresholds, metaIds, allLoopCountTraps);
    }
    removeIfEdgeInstrumentation(metaIds, elseArmTraps);
    removeDefaultBlockInstrumentation(metaIds, defaultSwitchTraps);
    removeSwitchFallthroughInstrumentation(metaIds, fellthroughSwitchTraps);
    removeInvokeInstrumentation(metaIds, invokeTraps);
    removeBlockInstrumentation(metaIds, blockTraps);
    removeLoopInstrumentation(metaIds, loopCountTraps);
    // Do this AFTER removeLoopInstrumentation: that call already erased
    // the entries in loopCountTraps (the retiring subset). Anything left
    // in allLoopCountTraps whose id isn't in metaIds is still alive and
    // may need its threshold restored.
    return writeToFile(*M, outputFile.data());
}