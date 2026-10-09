#include "DeEdge.h"

// Strips a Trap/Direct block down to nothing but its terminator branch.
// Leaves the block itself, its CaseBB predecessor, and the CondBr all intact —
// this is a "soft" removal, not a full teardown.
void neutralizeBlock(CallInst *Trap)
{
    BasicBlock *BB = Trap->getParent();
    BasicBlock *ContBB = BB->getUniqueSuccessor();
    if (!ContBB)
    {
        errs() << "[deinstr] ERROR neutralizeBlock: '" << BB->getName()
               << "' has no unique successor - aborting\n";
        assert(false && "expected trap/direct block to have a single successor");
        return;
    }

    SmallVector<Instruction *, 8> toErase;
    for (Instruction &I : *BB)
        if (&I != BB->getTerminator())
            toErase.push_back(&I);

    for (auto it = toErase.rbegin(); it != toErase.rend(); ++it)
    {
        if (!(*it)->use_empty())
        {
            errs() << "[deinstr] ERROR neutralizeBlock: '" << (*it)->getName()
                   << "' in '" << BB->getName() << "' still has "
                   << (*it)->getNumUses() << " use(s):\n";
            for (User *U : (*it)->users())
                U->print(errs()), errs() << "\n";
            assert(false && "unexpected use of instrumentation instruction");
        }
        (*it)->eraseFromParent();
    }

    if (!isNeutralized(BB))
    {
        errs() << "[deinstr] ERROR neutralizeBlock: '" << BB->getName()
               << "' did not reduce to a single unconditional br\n";
        assert(false && "block did not reduce to a single unconditional br");
    }
}

bool isNeutralized(BasicBlock *BB)
{
    if (&BB->front() != &BB->back())
        return false;
    auto *Br = dyn_cast<BranchInst>(&BB->front());
    return Br && Br->isUnconditional();
}

void collapseFallthroughSite(BasicBlock *CaseBB,
                             SmallVectorImpl<PHINode *> &preservedEntryPhis)
{
    auto *CondBr = dyn_cast<BranchInst>(CaseBB->getTerminator());
    if (!CondBr || !CondBr->isConditional())
    {
        errs() << "[deinstr] ERROR collapseFallthroughSite: '" << CaseBB->getName()
               << "' terminator is not a conditional br\n";
        assert(false && "expected CaseBB's CondBr");
        return;
    }
    BasicBlock *TrapBB = CondBr->getSuccessor(0);
    BasicBlock *DirectBB = CondBr->getSuccessor(1);
    BasicBlock *ContBB = TrapBB->getUniqueSuccessor();
    if (!ContBB || ContBB != DirectBB->getUniqueSuccessor())
    {
        errs() << "[deinstr] ERROR collapseFallthroughSite: '" << CaseBB->getName()
               << "' trap/direct successors don't converge to a matching ContBB\n";
        assert(false && "mismatched pair");
        return;
    }

    for (PHINode &PN : ContBB->phis())
    {
        int idx1 = PN.getBasicBlockIndex(TrapBB);
        int idx2 = PN.getBasicBlockIndex(DirectBB);
        if (idx1 >= 0)
            PN.setIncomingBlock(idx1, CaseBB);
        if (idx2 >= 0)
            PN.removeIncomingValue(idx2, /*DeletePHIIfEmpty=*/false);
    }

    PHINode *entryCase = dyn_cast<PHINode>(&CaseBB->front());

    Value *Cond = CondBr->getCondition();
    CondBr->eraseFromParent();
    IRBuilder<> Builder(CaseBB);
    Builder.CreateBr(ContBB);

    SmallVector<Instruction *, 8> chain;
    SmallPtrSet<Instruction *, 8> seenI;
    std::function<void(Value *)> collect = [&](Value *V)
    {
        auto *I = dyn_cast<Instruction>(V);
        if (!I || I == entryCase || I->getParent() != CaseBB)
            return;
        if (!seenI.insert(I).second)
            return;
        for (Use &U : I->operands())
            collect(U.get());
        chain.push_back(I);
    };
    collect(Cond);

    for (auto it = chain.rbegin(); it != chain.rend(); ++it)
    {
        if ((*it)->use_empty())
        {
            (*it)->eraseFromParent();
        }
        else
        {
            errs() << "[deinstr] ERROR collapseFallthroughSite: check-chain instr '"
                   << (*it)->getName() << "' in '" << CaseBB->getName()
                   << "' still has uses after CondBr removal (unexpected)\n";
        }
    }

    if (entryCase)
    {
        if (entryCase->use_empty())
            entryCase->eraseFromParent();
        else
            preservedEntryPhis.push_back(entryCase);
    }

    TrapBB->eraseFromParent();
    DirectBB->eraseFromParent();
}