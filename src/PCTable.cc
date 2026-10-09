#include "common.h"
#include "PCTablePass.h"

using namespace llvm;

void instrumentBlocks(Function &F, SmallPtrSet<BasicBlock *, 16> &seen, int &pctableCount)
{
    if (F.isDeclaration())
        return;
    LLVMContext &Ctx = F.getContext();
    Type *IdTy = Type::getInt32Ty(Ctx);

    for (BasicBlock &BB : F)
    {
        if (seen.count(&BB))
            continue;
        seen.insert(&BB);
        if (&BB == &F.getEntryBlock())
            continue;

        Instruction *InsertPt = &*BB.getFirstInsertionPt();
        IRBuilder<> IRB(InsertPt);

        int id = pctableCount++;
        uint32_t uid = static_cast<uint32_t>(id);
        unsigned b0 = uid & 0xFF, b1 = (uid >> 8) & 0xFF,
                 b2 = (uid >> 16) & 0xFF, b3 = (uid >> 24) & 0xFF;

        std::string AsmStr =
            ".byte 0xcc\n\t.byte " +
            std::to_string(b0) + ", " + std::to_string(b1) + ", " +
            std::to_string(b2) + ", " + std::to_string(b3) + "\n\t";
        FunctionType *AsmFTy = FunctionType::get(Type::getVoidTy(Ctx), false);
        InlineAsm *IA = InlineAsm::get(AsmFTy, AsmStr, "~{memory}", true);
        CallInst *TrapCall = IRB.CreateCall(IA);
        MDNode *MD = MDNode::get(Ctx, ConstantAsMetadata::get(ConstantInt::get(IdTy, id)));
        TrapCall->setMetadata("block_id", MD);
    }
}

void emitRegistrationCtor(llvm::Module &M, llvm::GlobalVariable *PCTable, llvm::Function &F)
{
    LLVMContext &Ctx = M.getContext();
    Type *VoidTy = Type::getVoidTy(Ctx);
    Type *PtrTy = PointerType::getUnqual(Ctx);

    FunctionCallee RegFn = M.getOrInsertFunction(
        "__runtime_register_pctable",
        FunctionType::get(VoidTy, {PtrTy, PtrTy}, /*isVarArg=*/false));

    std::string CtorName = "__pctable_ctor_" + F.getName().str();
    Function *Ctor = Function::Create(
        FunctionType::get(VoidTy, false),
        GlobalValue::InternalLinkage,
        CtorName,
        M);

    BasicBlock *Entry = BasicBlock::Create(Ctx, "entry", Ctor);
    IRBuilder<> IRB(Entry);

    Value *Start = IRB.CreateConstGEP2_32(
        PCTable->getValueType(),
        PCTable,
        0, 0, // [0][0]
        "pctable_start");

    uint64_t NumEntries = cast<ArrayType>(
                              PCTable->getValueType())
                              ->getNumElements();

    Value *End = IRB.CreateConstGEP2_32(
        PCTable->getValueType(),
        PCTable,
        0, NumEntries, // [0][N] — one past the end
        "pctable_end");

    // Call __runtime_register_pctable(start, end)
    IRB.CreateCall(RegFn, {Start, End});
    IRB.CreateRetVoid();

    appendToGlobalCtors(M, Ctor, /*Priority=*/65535);
}

// Builds the PC table for a single function
// Returns the created global, or nullptr if function has no blocks
GlobalVariable *buildPCTable(Function &F)
{
    // Skip declarations — no body to build a table from
    if (F.isDeclaration())
        return nullptr;

    LLVMContext &Ctx = F.getContext();
    Module *M = F.getParent();

    // i8* type — standard for block addresses
    Type *PtrTy = PointerType::getUnqual(Ctx);

    // -------------------------------------------------------
    // Collect a blockaddress constant for every basic block
    // -------------------------------------------------------
    std::vector<Constant *> Entries;
    for (BasicBlock &BB : F)
    {
        // Skip blocks already handled elsewhere (e.g. the dedicated
        // default/trap blocks you inserted)
        // Skip the entry block — blockaddress is not allowed on it
        if (&BB == &F.getEntryBlock())
            continue;

        BlockAddress *BA = BlockAddress::get(&F, &BB);
        Constant *Entry = ConstantExpr::getBitCast(BA, PtrTy);
        Entries.push_back(Entry);
    }

    if (Entries.empty())
        return nullptr;

    // -------------------------------------------------------
    // Build the global constant array
    // -------------------------------------------------------
    ArrayType *TableTy = ArrayType::get(PtrTy, Entries.size());
    Constant *TableInit = ConstantArray::get(TableTy, Entries);

    // Name it per-function so multiple functions don't collide
    std::string TableName = "__my_pctable_" + F.getName().str();

    GlobalVariable *PCTable = new GlobalVariable(
        *M,
        TableTy,
        /*isConstant=*/true,          // lives in .rodata
        GlobalValue::InternalLinkage, // not visible outside TU
        TableInit,
        TableName);

    // Ensure natural pointer alignment
    PCTable->setAlignment(MaybeAlign(8));

    return PCTable;
}