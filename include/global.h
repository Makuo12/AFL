#ifndef GLOBAL_H_
#define GLOBAL_H_
#include <stdio.h>
#include <stdint.h>
void free_ptrs(void);
void close_open_file_handles(void);
void __untracer_setup_global(void);
int __untracer_restore_global(void);
#endif