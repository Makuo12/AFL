#include "common.h"
#include "PCTablePass.h"
#include <string>
#include <map>
#include "Edge.h"

using namespace std;
using namespace llvm;

void handleSwitchFallthroughEdge(Instruction &TI, int &phiNodesInserted, SmallPtrSet<BasicBlock *, 16> &seen)
{
    auto *SI = dyn_cast<SwitchInst>(&TI);
    if (!SI)
        return;
    Function *F = TI.getFunction();
    Module *M = F->getParent();
    LLVMContext &Ctx = SI->getContext();
    Type *CondTy = SI->getCondition()->getType();
    BasicBlock *SwitchBB = SI->getParent();

    std::vector<std::pair<ConstantInt *, BasicBlock *>> directCases;
    for (auto Case : SI->cases())
        directCases.push_back({Case.getCaseValue(), Case.getCaseSuccessor()});

    SmallPtrSet<BasicBlock *, 16> switchCaseBlocks;
    for (auto &[val, bb] : directCases)
        switchCaseBlocks.insert(bb);

    DenseMap<BasicBlock *, BasicBlock *> contToOriginalCase;
    DenseMap<BasicBlock *, Value *> entryCaseAt;

    auto isChainMember = [&](BasicBlock *BB)
    {
        return switchCaseBlocks.count(BB) || contToOriginalCase.count(BB);
    };

    auto resolveToCase = [&](BasicBlock *BB) -> BasicBlock *
    {
        if (auto it = contToOriginalCase.find(BB); it != contToOriginalCase.end())
            return it->second;
        return BB;
    };

    auto findFallthroughPred = [&](BasicBlock *CaseBB) -> BasicBlock *
    {
        SmallVector<BasicBlock *, 4> candidates;
        for (BasicBlock *Pred : predecessors(CaseBB))
        {
            if (Pred == SwitchBB)
                continue;
            if (!isChainMember(Pred))
                continue;
            candidates.push_back(Pred);
        }
        if (candidates.empty())
            return nullptr;
        if (candidates.size() > 1)
        {
            for (BasicBlock *C : candidates)
                return nullptr;
        }
        return candidates[0];
    };

    // Builds a fresh, single-use InlineAsm for a 0xcc trap with `id`
    // encoded as 4 raw little-endian bytes immediately after the trap
    // byte — same convention as the other edge-instrumentation sites.
    // The runtime reads these directly off the SIGTRAP return address
    // instead of decoding any instruction, so the offset (trap+1) is
    // fixed regardless of codegen. A distinct InlineAsm object is built
    // per id since the id is baked into the asm string itself.
    auto makeTrapAsm = [&](int id) -> InlineAsm *
    {
        uint32_t uid = static_cast<uint32_t>(id);
        unsigned b0 = uid & 0xFF;
        unsigned b1 = (uid >> 8) & 0xFF;
        unsigned b2 = (uid >> 16) & 0xFF;
        unsigned b3 = (uid >> 24) & 0xFF;
        std::string AsmStr =
            ".byte 0xcc\n\t"
            ".byte " +
            std::to_string(b0) + ", " + std::to_string(b1) + ", " +
            std::to_string(b2) + ", " + std::to_string(b3) + "\n\t";
        FunctionType *AsmFTy =
            FunctionType::get(Type::getVoidTy(Ctx), /*isVarArg=*/false);
        return InlineAsm::get(
            AsmFTy, AsmStr,
            /*Constraints=*/"~{memory}",
            /*hasSideEffects=*/true);
    };

    auto processOne = [&](BasicBlock *CaseBB)
    {
        if (entryCaseAt.count(CaseBB))
            return; // already done
        std::vector<ConstantInt *> ownValues;
        for (auto &[val, bb] : directCases)
            if (bb == CaseBB)
                ownValues.push_back(val);

        BasicBlock *fallthroughPred = findFallthroughPred(CaseBB);

        if (!fallthroughPred || ownValues.empty())
        {
            entryCaseAt[CaseBB] = ownValues.empty() ? nullptr : ownValues[0];
            return;
        }
        BasicBlock *predCaseBB = resolveToCase(fallthroughPred);
        Value *predEntryCase = entryCaseAt.count(predCaseBB) ? entryCaseAt[predCaseBB] : nullptr;
        if (!predEntryCase)
        {
            entryCaseAt[CaseBB] = ownValues[0];
            return;
        }

        BasicBlock *ContBB = SplitBlock(CaseBB, &CaseBB->front());
        ContBB->setName(CaseBB->getName() + ".cont");
        contToOriginalCase[ContBB] = CaseBB;
        CaseBB->getTerminator()->eraseFromParent();
        IRBuilder<> B(CaseBB);

        PHINode *entryCase = B.CreatePHI(CondTy, 4, CaseBB->getName() + ".entry");
        entryCase->dropDbgRecords();
        for (BasicBlock *Pred : predecessors(CaseBB))
        {
            if (Pred == fallthroughPred)
                entryCase->addIncoming(predEntryCase, Pred);
            else
                entryCase->addIncoming(ownValues[0], Pred);
        }

        Value *isDirect = B.getFalse();
        for (ConstantInt *v : ownValues)
        {
            SmallString<16> Buf;
            v->getValue().toString(Buf, 10, true);
            std::string name = (CaseBB->getName() + ".eq." + Buf).str();
            Value *eq = B.CreateICmpEQ(entryCase, v, name);
            isDirect = B.CreateOr(isDirect, eq);
        }
        Value *fellThrough = B.CreateNot(isDirect, CaseBB->getName() + ".fellthrough");

        BasicBlock *TrapBB = BasicBlock::Create(Ctx, CaseBB->getName() + ".trap", CaseBB->getParent());
        BasicBlock *DirectBB = BasicBlock::Create(Ctx, CaseBB->getName() + ".direct", CaseBB->getParent());
        B.CreateCondBr(fellThrough, TrapBB, DirectBB);

        // Dedicated, uniquely-named i32 globals so each block's marker store has a
        // distinct pointer operand. This is what actually blocks SimplifyCFG's
        // block-merging: two calls to structurally-identical code followed by the
        // same branch target WILL be folded together, no matter how differently
        // the source blocks are named. A volatile store to a distinct global
        // operand is not foldable that way. (Unrelated to id encoding — these
        // markers are purely an anti-CSE/anti-merge device.)
        auto makeMarker = [&](StringRef suffix) -> GlobalVariable *
        {
            std::string gname = ("__cfi_marker." + CaseBB->getName() + suffix).str();
            auto *GV = cast<GlobalVariable>(
                M->getOrInsertGlobal(gname, Type::getInt32Ty(Ctx)));
            if (!GV->hasInitializer())
            {
                GV->setInitializer(ConstantInt::get(Type::getInt32Ty(Ctx), 0));
                GV->setLinkage(GlobalValue::PrivateLinkage);
            }
            return GV;
        };

        GlobalVariable *TrapMarker = makeMarker(".trapmark");
        GlobalVariable *DirectMarker = makeMarker(".directmark");

        Type *Int32Ty = Type::getInt32Ty(Ctx);
        int trapId = phiNodesInserted++;
        int directId = phiNodesInserted++;

        MDNode *TrapMD = MDNode::get(Ctx, ConstantAsMetadata::get(ConstantInt::get(Int32Ty, trapId)));
        MDNode *DirectMD = MDNode::get(Ctx, ConstantAsMetadata::get(ConstantInt::get(Int32Ty, directId)));

        IRBuilder<> BT(TrapBB);
        BT.CreateStore(ConstantInt::get(Type::getInt32Ty(Ctx), 1), TrapMarker, /*isVolatile=*/true);
        CallInst *TrapCall = BT.CreateCall(makeTrapAsm(trapId));
        TrapCall->setMetadata("switch_fallthrough_id", TrapMD);
        BT.CreateBr(ContBB);

        IRBuilder<> BD(DirectBB);
        BD.CreateStore(ConstantInt::get(Type::getInt32Ty(Ctx), 1), DirectMarker, /*isVolatile=*/true);
        CallInst *DirectCall = BD.CreateCall(makeTrapAsm(directId));
        DirectCall->setMetadata("switch_fallthrough_id", DirectMD);
        BD.CreateBr(ContBB);

        entryCaseAt[CaseBB] = entryCase;
        seen.insert(TrapBB);
        seen.insert(DirectBB);
    };

    for (auto &[val, topBB] : directCases)
    {
        if (entryCaseAt.count(topBB))
            continue;

        std::vector<BasicBlock *> stack;
        SmallPtrSet<BasicBlock *, 8> onThisWalk;

        BasicBlock *cur = topBB;
        while (cur && !entryCaseAt.count(cur))
        {
            if (!onThisWalk.insert(cur).second)
            {
                cur = nullptr;
                break;
            }
            stack.push_back(cur);
            BasicBlock *pred = findFallthroughPred(cur);
            cur = pred ? resolveToCase(pred) : nullptr;
        }
        for (auto it = stack.rbegin(); it != stack.rend(); ++it)
            processOne(*it);
    }
}

void handleDefaultBlockEdge(Instruction &TI, int &defaultAddedCount, SmallPtrSet<BasicBlock *, 16> &seen)
{
    auto *SI = dyn_cast<SwitchInst>(&TI);
    if (!SI)
        return;
    LLVMContext &Ctx = SI->getContext();
    Function *F = SI->getFunction();
    Type *Int32Ty = Type::getInt32Ty(Ctx);
    BasicBlock *OldDefaultDest = SI->getDefaultDest();
    int id = defaultAddedCount++;
    std::string blockName = "sw.default.dedicated" + std::to_string(id);
    BasicBlock *NewDefaultBB = BasicBlock::Create(Ctx, blockName, F, OldDefaultDest);
    SI->setDefaultDest(NewDefaultBB);
    IRBuilder<> Builder(NewDefaultBB);

    // Encode id as 4 little-endian raw bytes placed right after the
    // 0xcc trap byte — same convention as the other edge-instrumentation
    // sites (else-edge, invoke, switch-fallthrough). The runtime reads
    // these directly off the SIGTRAP return address instead of decoding
    // any instruction, so the offset (trap+1) is fixed regardless of
    // codegen.
    uint32_t uid = static_cast<uint32_t>(id);
    unsigned b0 = uid & 0xFF;
    unsigned b1 = (uid >> 8) & 0xFF;
    unsigned b2 = (uid >> 16) & 0xFF;
    unsigned b3 = (uid >> 24) & 0xFF;
    std::string AsmStr =
        ".byte 0xcc\n\t"
        ".byte " +
        std::to_string(b0) + ", " + std::to_string(b1) + ", " +
        std::to_string(b2) + ", " + std::to_string(b3) + "\n\t";
    FunctionType *AsmFTy =
        FunctionType::get(Type::getVoidTy(Ctx), /*isVarArg=*/false);
    InlineAsm *IA = InlineAsm::get(
        AsmFTy, AsmStr,
        /*Constraints=*/"~{memory}",
        /*hasSideEffects=*/true);

    CallInst *TrapCall = Builder.CreateCall(IA);
    MDNode *MD = MDNode::get(Ctx, ConstantAsMetadata::get(ConstantInt::get(Int32Ty, id)));
    TrapCall->setMetadata("default_block_id", MD);
    Builder.CreateBr(OldDefaultDest);
    for (PHINode &PN : OldDefaultDest->phis())
    {
        int Idx = PN.getBasicBlockIndex(SI->getParent());
        if (Idx >= 0)
            PN.setIncomingBlock(Idx, NewDefaultBB);
    }
    seen.insert(NewDefaultBB);
}

void handleInvokeEdges(Instruction &TI, int &invokeAddedCount, SmallPtrSet<BasicBlock *, 16> &seen)
{
    auto *II = dyn_cast<InvokeInst>(&TI);
    if (!II)
        return;
    LLVMContext &Ctx = II->getContext();
    Function *F = II->getFunction();
    Type *Int32Ty = Type::getInt32Ty(Ctx);

    FunctionType *AsmFTy =
        FunctionType::get(Type::getVoidTy(Ctx), /*isVarArg=*/false);

    for (unsigned i = 0, e = II->getNumSuccessors(); i != e; ++i)
    {
        BasicBlock *EdgeBB = II->getSuccessor(i);
        // Only instrument the normal-dest edge (i == 0).
        // The unwind edge already has valid, self-contained EH handling
        // (landingpad -> catch/terminate/resume) and must not be spliced
        // with a plain block (see earlier verifier errors).
        if (i != 0)
            continue;
        BasicBlock *NormalDest = EdgeBB;
        int id = invokeAddedCount++;
        MDNode *MD = MDNode::get(Ctx, ConstantAsMetadata::get(ConstantInt::get(Int32Ty, id)));

        // Encode id as 4 little-endian raw bytes placed right after the
        // 0xcc trap byte — same convention as the else-edge and loop
        // guard sites. The runtime reads these directly off the
        // SIGTRAP return address instead of decoding any instruction,
        // so the offset (trap+1) is fixed regardless of codegen.
        uint32_t uid = static_cast<uint32_t>(id);
        unsigned b0 = uid & 0xFF;
        unsigned b1 = (uid >> 8) & 0xFF;
        unsigned b2 = (uid >> 16) & 0xFF;
        unsigned b3 = (uid >> 24) & 0xFF;
        std::string AsmStr =
            ".byte 0xcc\n\t"
            ".byte " +
            std::to_string(b0) + ", " + std::to_string(b1) + ", " +
            std::to_string(b2) + ", " + std::to_string(b3) + "\n\t";
        InlineAsm *IA = InlineAsm::get(
            AsmFTy, AsmStr,
            /*Constraints=*/"~{memory}",
            /*hasSideEffects=*/true);

        if (NormalDest->getSinglePredecessor() == II->getParent())
        {
            // Only this invoke reaches NormalDest — safe to instrument in place,
            // right after any PHI nodes.
            IRBuilder<> Builder(NormalDest->getFirstNonPHI());
            CallInst *TrapCall = Builder.CreateCall(IA);
            TrapCall->setMetadata("invoke_block_id", MD);
            seen.insert(NormalDest);
        }
        else
        {
            // NormalDest is shared with other predecessors (critical edge) —
            // splice a private block so the trap fires only for THIS invoke's
            // success path, not for every path into the shared block.
            std::string blockName = "invoke.cont" + std::to_string(id);
            BasicBlock *NewBlock = BasicBlock::Create(Ctx, blockName, F, NormalDest);
            II->setSuccessor(i, NewBlock);
            IRBuilder<> Builder(NewBlock);
            CallInst *TrapCall = Builder.CreateCall(IA);
            TrapCall->setMetadata("invoke_block_id", MD);
            Builder.CreateBr(NormalDest);
            for (PHINode &PN : NormalDest->phis())
            {
                int Idx = PN.getBasicBlockIndex(II->getParent());
                if (Idx >= 0)
                    PN.setIncomingBlock(Idx, NewBlock);
            }
            seen.insert(NewBlock);
        }
    }
}

void countCriticalEdge(Instruction &TI, int &globalCount, int &criticalEdgeCount)
{
    for (unsigned i = 0, e = TI.getNumSuccessors(); i != e; ++i)
    {
        if (isCriticalEdge(&TI, i))
        {
            ++globalCount;
            ++criticalEdgeCount;
        }
    }
}

void handleIfEdges(Instruction &TI, int &count, SmallPtrSet<BasicBlock *, 16> &seen)
{
    auto *BI = dyn_cast<BranchInst>(&TI);
    if (!BI)
    {
        return;
    }
    LLVMContext &Ctx = TI.getContext();
    Function *F = TI.getFunction();
    Module *M = F->getParent();
    BasicBlock *BB = TI.getParent();
    Type *Int32Ty = Type::getInt32Ty(M->getContext());
    for (unsigned i = 0, e = TI.getNumSuccessors(); i != e; ++i)
    {
        if (isCriticalEdge(&TI, i))
        {
            BasicBlock *FalseBB = BI->getSuccessor(i);
            if (pred_size(FalseBB) > 1)
            {
                int id = count++;
                string name = "if.else.new";
                name += std::to_string(id);
                BasicBlock *NewElseBB = BasicBlock::Create(Ctx, name, F, FalseBB);
                BI->setSuccessor(i, NewElseBB);
                for (PHINode &PN : FalseBB->phis())
                {
                    int idx = PN.getBasicBlockIndex(BB);
                    if (idx >= 0)
                        PN.setIncomingBlock(idx, NewElseBB);
                }
                IRBuilder<> Builder(NewElseBB);

                // Encode id as 4 little-endian raw bytes placed right
                // after the 0xcc trap byte — same convention as the
                // loop guard's 0xf1 site. The runtime reads these
                // directly off the SIGTRAP return address instead of
                // decoding any instruction, so the offset (trap+1) is
                // fixed regardless of codegen.
                uint32_t uid = static_cast<uint32_t>(id);
                unsigned b0 = uid & 0xFF;
                unsigned b1 = (uid >> 8) & 0xFF;
                unsigned b2 = (uid >> 16) & 0xFF;
                unsigned b3 = (uid >> 24) & 0xFF;

                FunctionType *AsmFTy =
                    FunctionType::get(Type::getVoidTy(Ctx), /*isVarArg=*/false);

                // No operands needed — this is an unconditional trap,
                // not a guarded counter, so there's nothing to pass in
                // and therefore nothing for the allocator to place in
                // a variable register. The .byte sequence is fixed,
                // byte-for-byte, at every call site.
                std::string AsmStr =
                    ".byte 0xcc\n\t"
                    ".byte " +
                    std::to_string(b0) + ", " + std::to_string(b1) + ", " +
                    std::to_string(b2) + ", " + std::to_string(b3) + "\n\t";

                InlineAsm *IA = InlineAsm::get(
                    AsmFTy, AsmStr,
                    /*Constraints=*/"~{memory}",
                    /*hasSideEffects=*/true);

                // This call wraps the 0xcc trap byte (and the raw id
                // bytes right after it) — tag it directly with the id
                // metadata, same convention as the loop guard site.
                CallInst *TrapCall = Builder.CreateCall(IA);
                MDNode *MD = MDNode::get(Ctx, ConstantAsMetadata::get(ConstantInt::get(Int32Ty, id)));
                TrapCall->setMetadata("else_block_id", MD);

                Builder.CreateBr(FalseBB);
                seen.insert(NewElseBB);
            }
        }
    }
}

void processModule(Module &M, Function &F, int &globalCount, map<string, BlockInfo> &blocks)
{
    if (F.isDeclaration())
        return;
    for (BasicBlock &BB : llvm::make_early_inc_range(F))
    {
        int criticalIndex = -1;
        Instruction *TI = BB.getTerminator();
        switch (TI->getOpcode())
        {
        case Instruction::Ret:
            ++blocks["Ret"].blockCount;
            countCriticalEdge(*TI, globalCount, blocks["Ret"].criticalEdgeCount);
            break;
        case Instruction::Br:
            ++blocks["Br"].blockCount;
            countCriticalEdge(*TI, globalCount, blocks["Br"].criticalEdgeCount);
            break;
        case Instruction::Switch:
            ++blocks["Switch"].blockCount;
            countCriticalEdge(*TI, globalCount, blocks["Switch"].criticalEdgeCount);
            break;
        case Instruction::IndirectBr:
            ++blocks["IndirectBr"].blockCount;
            countCriticalEdge(*TI, globalCount, blocks["IndirectBr"].criticalEdgeCount);
            break;
        case Instruction::Invoke:
            ++blocks["Invoke"].blockCount;
            countCriticalEdge(*TI, globalCount, blocks["Invoke"].criticalEdgeCount);
            break;
        case Instruction::CallBr:
            ++blocks["CallBr"].blockCount;
            countCriticalEdge(*TI, globalCount, blocks["CallBr"].criticalEdgeCount);
            break;
        case Instruction::Resume:
            ++blocks["Resume"].blockCount;
            countCriticalEdge(*TI, globalCount, blocks["Resume"].criticalEdgeCount);
            break;
        case Instruction::CatchSwitch:
            ++blocks["CatchSwitch"].blockCount;
            countCriticalEdge(*TI, globalCount, blocks["CatchSwitch"].criticalEdgeCount);
            break;
        case Instruction::CatchRet:
            ++blocks["CatchRet"].blockCount;
            countCriticalEdge(*TI, globalCount, blocks["CatchRet"].criticalEdgeCount);
            break;
        case Instruction::CleanupRet:
            ++blocks["CleanupRet"].blockCount;
            countCriticalEdge(*TI, globalCount, blocks["CleanupRet"].criticalEdgeCount);
            break;
        case Instruction::Unreachable:
            ++blocks["Unreachable"].blockCount;
            countCriticalEdge(*TI, globalCount, blocks["Unreachable"].criticalEdgeCount);
            break;
        }
    }
}

void handlePCTable(Function &F, Module &M)
{
    GlobalVariable *Table = buildPCTable(F);
    if (!Table)
        return; // no blocks — nothing to instrument
    // Step 2 — emit the registration constructor
    emitRegistrationCtor(M, Table, F);
}