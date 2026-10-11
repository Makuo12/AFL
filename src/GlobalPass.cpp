#include "GlobalPass.h"
#include <fstream>
#include <iostream>
#define CLOSURE_GLOBAL_SECTION = "__cls_glob"
/**
 * @brief Method for adding a copy of each global variable, and calls
 * restoreGlobalVariables which adds a load and store inst to initialize the
 * variables from their shadow backups
 *
 * @param M
 */
void CloneGlobalsPass::cloneGlobals(Module &M)
{

    for (auto &Global : M.globals())
    {
        if (Global.hasSection() == false && Global.isConstant() == false)
        {
            #ifdef __linux__
            Global.setSection("__cls_glob");
            #elif defined(__APPLE__) && defined(__aarch64__)
            Global.setSection("DATA,__cls_glob");
            #endif
        }
    }
}

/**
 * @brief runOnModule method for Module Pass
 *
 * @param M
 * @return true
 * @return false
 */
bool CloneGlobalsPass::runOnModule(Module &M)
{
    // if (isClosureStubModule(M.getName()))
    // {
    //     return false;
    // }

    cloneGlobals(M);
    return true;
}

PreservedAnalyses CloneGlobalsPass::run(Module &M, ModuleAnalysisManager &AM)
{

    runOnModule(M);
    return PreservedAnalyses::none();
}
