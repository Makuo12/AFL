#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "global.h"

/*
 * Linux-only global snapshot/restore.
 *
 * The CloneGlobalsPass (or a manual __attribute__((section("__cls_glob"))))
 * places every tracked global in the "__cls_glob" section. Because that name
 * is a valid C identifier, GNU ld defines __start___cls_glob and
 * __stop___cls_glob around it. They are weak so the program still links
 * (and we can report it) when no global ended up in the section.
 */
#ifdef __cplusplus
extern "C"
{
#endif

    extern char __start___cls_glob[] __attribute__((weak));
    extern char __stop___cls_glob[] __attribute__((weak));

/*
 * The runtime's own state lives in a different section so it is never part
 * of the snapshot. Otherwise a restore would roll back `ready` and
 * `snapshot` themselves. The pass skips globals that already have a section.
 */
#define KEEP __attribute__((section("untracer_state")))

    static KEEP char *snapshot = NULL;
    static KEEP size_t snapshot_size = 0;
    static KEEP int ready = 0;

    /* Call once, after static initialization (e.g. at the start of main). */
    void __untracer_setup_global(void)
    {
        char *start = __start___cls_glob;
        char *stop = __stop___cls_glob;

        if (!start || start == stop)
        {
            fprintf(stderr, "Error: section __cls_glob is missing or empty\n");
            return;
        }

        snapshot_size = (size_t)(stop - start);
        snapshot = (char *)malloc(snapshot_size);
        if (!snapshot)
        {
            perror("malloc");
            snapshot_size = 0;
            return;
        }

        memcpy(snapshot, start, snapshot_size);
        ready = 1;
    }

    /* Returns 0 on success, -1 if setup did not succeed. */
    int __untracer_restore_global(void)
    {
        if (!ready)
            return -1;

        /* Globals are in a writable data section, so no mprotect is needed. */
        memcpy(__start___cls_glob, snapshot, snapshot_size);
        return 0;
    }

#ifdef __cplusplus
}
#endif