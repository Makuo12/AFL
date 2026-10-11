/**
 * This pass is for renaming the main function of the desired piece of code.
 */

#include "HeapPass.h"

/**
 * @brief Replaces free and malloc with my own implementation of free and malloc from the
 * main stub
 *
 * @param M
 */
void HeapResetPass::heapManage(Module &M)
{
    auto freeFunc = M.getFunction("free");
    auto mallocFunc = M.getFunction("malloc");
    auto callocFunc = M.getFunction("calloc");
    auto reallocFunc = M.getFunction("realloc");

    if (mallocFunc != nullptr)
    {
        errs() << "[HeapPass] Found malloc: " << mallocFunc->getName() << "\n";
        errs() << "[HeapPass] Type: " << *mallocFunc->getFunctionType() << "\n";

        auto myMalloc = M.getOrInsertFunction("myMalloc", mallocFunc->getFunctionType());
        errs() << "[HeapPass] myMalloc callee: " << *myMalloc.getCallee() << "\n";

        mallocFunc->replaceAllUsesWith(myMalloc.getCallee());
        errs() << "[HeapPass] replaced all uses\n";
        // mallocFunc->eraseFromParent();
    }
    if (callocFunc != nullptr)
    {
        // We have calls to malloc in this module, replace them
        auto myCalloc = M.getOrInsertFunction("myCalloc", callocFunc->getFunctionType());
        callocFunc->replaceAllUsesWith(myCalloc.getCallee());
    }
    if (reallocFunc != nullptr)
    {
        // We have calls to malloc in this module, replace them
        auto myRealloc = M.getOrInsertFunction("myRealloc", reallocFunc->getFunctionType());
        reallocFunc->replaceAllUsesWith(myRealloc.getCallee());
    }
    if (freeFunc != nullptr)
    {
        // We have calls to free in this module, replace them
        auto myFree = M.getOrInsertFunction("myFree", freeFunc->getFunctionType());

        freeFunc->replaceAllUsesWith(myFree.getCallee());
    }
}

/**
 * @brief runOnModule method for Module Pass
 *
 * @param M
 * @return true
 * @return false
 */
bool HeapResetPass::runOnModule(Module &M)
{

    // if (isClosureStubModule(M.getName()))
    // {
    //     return false;
    // }

    heapManage(M);
    return true;
}

PreservedAnalyses HeapResetPass::run(Module &M, ModuleAnalysisManager &AM)
{

    runOnModule(M);
    return PreservedAnalyses::none();
}
