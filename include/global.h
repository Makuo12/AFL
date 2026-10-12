#ifndef GLOBAL_H_
#define GLOBAL_H_
#include <stdio.h>
#include <stdint.h>
void free_ptrs(void);
void close_open_file_handles(void);

/* Defined in global.c; C linkage so they link whether global.c is compiled
 * as C or C++ and whether the caller is C or C++. */
#ifdef __cplusplus
extern "C"
{
#endif
    void __untracer_setup_global(void);
    int __untracer_restore_global(void);
    void __untracer_snapshot_fds(void);
    void __untracer_heap_start(void);
    void __untracer_heap_pause(void);
    void __untracer_heap_resume(void);
    void __untracer_heap_reset(void);
#ifdef __cplusplus
}
#endif

#endif