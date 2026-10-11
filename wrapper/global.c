#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>
#include "global.h"
#ifdef __APPLE__
#include <mach-o/getsect.h>
#include <mach-o/dyld.h>
extern const struct mach_header_64 _mh_execute_header;
#endif

static void *copy_memory = NULL;
static uint64_t addr = 0;
static ssize_t size = 0;
static unsigned int reset_globals = 0;

void __untracer_make_writable(uint64_t addr)
{
    // align down to page boundary
    long page_size = sysconf(_SC_PAGESIZE);
    uint64_t page = addr & ~(page_size - 1);
    mprotect((void *)page, page_size, PROT_READ | PROT_WRITE | PROT_EXEC);
}

void __untracer_restore_global_sections(char *target, char *source, ssize_t len)
{
    __untracer_make_writable((uint64_t)target);
    memcpy(target, source, len);
}

int __untracer_restore_global(void)
{
    if (reset_globals != 0 && addr != 0 && size != 0)
    {
        __untracer_restore_global_sections((char *)addr, (char *)copy_memory, size);
        return 0;
    } else {
        return -1;
    }
}


void __untracer_setup_global(void)
{
#ifdef __APPLE__
    unsigned long section_size;
    uint8_t *section_addr = getsectiondata(&_mh_execute_header, "__DATA", "__cls_glob", &section_size);
    if (section_addr == NULL)
    {
        fprintf(stderr, "Error: Could not find section __DATA,__cls_glob\n");
        return;
    }
#elif __linux__
    extern char __start___cls_glob[] __attribute__((weak));
    extern char __stop___cls_glob[] __attribute__((weak));

    if (__start___cls_glob == NULL || __start___cls_glob == __stop___cls_glob)
    {
        fprintf(stderr, "Error: Could not find section .cls_glob\n");
        return;
    }
    uint8_t *section_addr = (uint8_t *)__start___cls_glob;
    unsigned long section_size = (unsigned long)(__stop___cls_glob - __start___cls_glob);
#endif

    addr = (unsigned long)section_addr;
    size = section_size;

    printf("Runtime Address: %p\n", (void *)section_addr);
    printf("Section Size:    %lu bytes\n", size);

    copy_memory = malloc(size);
    if (!copy_memory)
    {
        perror("malloc");
        return;
    }
    memcpy(copy_memory, section_addr, size);
    reset_globals = 1;
}