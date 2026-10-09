#define _GNU_SOURCE
#include <getopt.h>
#include <sys/ucontext.h>
#include <errno.h>
#include <inttypes.h>
#include <stdarg.h> /* va_list, used by log_line() in startup.c */
#include <signal.h>
#include <sys/mman.h>
#include <sys/shm.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include "uthash.h"
#include "data.h"
#include "config.h"
#ifdef __APPLE__
#include <mach-o/getsect.h>
#include <mach-o/dyld.h>
extern const struct mach_header_64 _mh_execute_header;
#endif

/* ------------------------------------------------------------------ */
/* Prototypes for externally-defined symbols                          */
/* ------------------------------------------------------------------ */

extern int target_main(int argc, char **argv);

typedef unsigned char u8;

int check = 0;

/* ------------------------------------------------------------------ */
/* Globals                                                            */
/* ------------------------------------------------------------------ */

Trace *addresses;
u8 *trace_bits; /* SHM with instrumentation bitmap  */

u8 count[MAP_SIZE]; /* SHM with instrumentation bitmap  */

int current_address = 0;

/* Maps a trap address -> index into addresses[], so repeated hits at the
   same trap site update the existing slot instead of allocating a new
   one. */
typedef struct
{
    uintptr_t key;
    int32_t index;
    UT_hash_handle hh;
} map;

map *hash_map = NULL;

/* Tracks pages already mprotect'd writable, so repeated trap hits in the
   same page don't re-issue the syscall. */
typedef struct
{
    uintptr_t page;
    UT_hash_handle hh;
} writable_page;

writable_page *writable_pages = NULL;

/* ------------------------------------------------------------------ */
/* Logging helper (NOT safe to call from signal handlers)             */
/* ------------------------------------------------------------------ */

void log_line(const char *fmt, ...)
{
    FILE *log_file = fopen("./output/trap_handler.log", "a");
    if (!log_file)
        log_file = stderr; // fallback

    va_list ap;
    va_start(ap, fmt);
    vfprintf(log_file, fmt, ap);
    va_end(ap);

    if (log_file != stderr)
        fclose(log_file);
}

/* ------------------------------------------------------------------ */
/* Async-signal-safe logging, for use inside signal handlers          */
/* ------------------------------------------------------------------ */

static void sig_log(const char *msg)
{
    /* write() is async-signal-safe; fopen/fprintf/fclose are not. */
    size_t len = strlen(msg);
    ssize_t ignored = write(STDERR_FILENO, msg, len);
    (void)ignored;
}

/* ------------------------------------------------------------------ */
/* Breakpoint map helpers                                             */
/* ------------------------------------------------------------------ */

map *__fuzzer_find_breakpoint(map *hash_map, uintptr_t key)
{
    map *entry = NULL;
    HASH_FIND(hh, hash_map, &key, sizeof(uintptr_t), entry);
    return entry; // NULL if not found
}

void __fuzzer_add_breakpoint(map **hash_map, uintptr_t key, int32_t index)
{
    map *entry = (map *)malloc(sizeof(map));

    entry->key = key;
    entry->index = index;

    HASH_ADD(hh, *hash_map, key, sizeof(uintptr_t), entry);
}

/* ------------------------------------------------------------------ */
/* Page protection                                                    */
/* ------------------------------------------------------------------ */

void make_range_writable(uintptr_t start, uintptr_t end)
{
    size_t page_size = sysconf(_SC_PAGESIZE);
    uintptr_t page = start & ~(page_size - 1);
    uintptr_t last_page = (end + 4) & ~(page_size - 1); // cover end..end+4 too

    for (; page <= last_page; page += page_size)
    {
        writable_page *found;
        HASH_FIND(hh, writable_pages, &page, sizeof(uintptr_t), found);

        if (found)
            continue; /* already writable - skip the syscall */

        if (mprotect((void *)page, page_size, PROT_READ | PROT_WRITE | PROT_EXEC) != 0)
        {
            perror("mprotect failed to write \n");
            exit(EXIT_FAILURE);
        }

        writable_page *entry = (writable_page *)malloc(sizeof(writable_page));
        entry->page = page;
        HASH_ADD(hh, writable_pages, page, sizeof(uintptr_t), entry);
    }
}

static inline u8 bucket_of(int32_t cmp)
{
    int32_t b = (cmp <= LOOP_START_ADD_5) ? cmp : 4 + cmp / 5;
    return b > 255 ? 255 : (b < 0 ? 0 : b);
}

/* ------------------------------------------------------------------ */
/* Signal handlers                                                    */
/* ------------------------------------------------------------------ */

void trap_handler(int sig, siginfo_t *info, void *ctx)
{
    ucontext_t *uc = (ucontext_t *)ctx;
#ifdef __linux__
    uintptr_t rip = uc->uc_mcontext.gregs[REG_RIP];
#elif defined(__APPLE__) && defined(__x86_64__)
    uintptr_t rip = uc->uc_mcontext->__ss.__rip;
#elif defined(__APPLE__) && defined(__aarch64__)
    uintptr_t rip = uc->uc_mcontext->__ss.__pc;
#endif
    uintptr_t addr = (uintptr_t)rip - 1;

    if (addr < 0x400000)
    {
        sig_log("addr underflow, base address assumption wrong\n");
        raise(SIGKILL);
        return;
    }

    off_t addr_offset = addr - 0x400000;
    (void)addr_offset; /* only used in the error branch below */

    make_range_writable(addr - 7, addr + 9);

    uintptr_t resume_addr = 0;
    unsigned char *trap = (unsigned char *)addr;
    int32_t value = 0, new_value = 0, index_block = 0;
    int32_t is_edge_count;

    // Loop-counter layout:  0xcc 0x90 0x90 0x90 0x90 id0 id1 id2 id3   (9 bytes)
    // Edge-counter layout:  0xcc id0 id1 id2 id3                       (5 bytes)
    // The old scheme used a second 0xcc to mark "this is a loop counter,"
    // which was ambiguous whenever an edge id's first byte was itself 0xcc
    // (~1 in 256 ids). Using a 4-byte 0x90 marker instead shrinks that
    // collision to needing all four bytes of an id to equal 0x90
    // (~1 in 4 billion) — infeasible given realistic id counts.
    if (*trap == 0xcc && trap[1] == 0x90 && trap[2] == 0x90 && trap[3] == 0x90 && trap[4] == 0x90)
    {
        uintptr_t cmp_addr = addr - 7;
        uintptr_t num_addr = cmp_addr + 1;
        memcpy(&value, (void *)num_addr, sizeof(value));
        if (value < 5)
            new_value = value + 1;
        else
            new_value = value + 5;

        uintptr_t index_addr = addr + 5; // skip trap byte + 4-byte 0x90 marker
        memcpy(&index_block, (void *)index_addr, sizeof(index_block));

        if (new_value >= MAX_LOOP)
        {
            memset(trap, 0x90, 9); // whole 9-byte region
            resume_addr = addr + 9;
        }
        else
        {
            memcpy((void *)num_addr, &new_value, sizeof(new_value));
            resume_addr = cmp_addr;
        }
        is_edge_count = 1;
        if (check) {
            count[index_block] = new_value;
        } else {
            trace_bits[index_block] = bucket_of(new_value);
        }
        log_line("loop counter hit index %d, value %d\n", index_block, new_value);
    }
    else if (*trap == 0xcc)
    {
        uintptr_t index_addr = addr + 1;
        memcpy(&index_block, (void *)index_addr, sizeof(index_block));
        memset(trap, 0x90, 5);
        resume_addr = addr + 5;
        is_edge_count = 0;
        if (check)
        {
            count[index_block] = 1;
        }
        else
        {
            trace_bits[index_block] = 1;
        }
        log_line("normal hit index %d, value %d\n", index_block, 1);
    }
    else
    {
        sig_log("failed to decode trap at unexpected address\n");
        raise(SIGKILL);
        return;
    }

    if (!check) {
        if (current_address < MAP_SIZE)
        {
            map *found = __fuzzer_find_breakpoint(hash_map, addr);
            if (found)
            {
                addresses[found->index].index = index_block;
                addresses[found->index].cmp_value = new_value;
                addresses[found->index].addr = addr;
                addresses[found->index].is_edge_count = is_edge_count;
            }
            else
            {
                __fuzzer_add_breakpoint(&hash_map, addr, current_address);
                addresses[current_address].index = index_block;
                addresses[current_address].cmp_value = new_value;
                addresses[current_address].is_edge_count = is_edge_count;
                addresses[current_address++].addr = addr;
            }
        }
        else
        {
            sig_log("overflow of addresses\n");
            raise(SIGKILL);
            return;
        }
    }

#ifdef __linux__
    uc->uc_mcontext.gregs[REG_RIP] = resume_addr;
#elif defined(__APPLE__) && defined(__x86_64__)
    uc->uc_mcontext->__ss.__rip = resume_addr;
#elif defined(__APPLE__) && defined(__aarch64__)
    uc->uc_mcontext->__ss.__pc = resume_addr;
#endif
    return;
}

void illegal_instruction_handler(int sig, siginfo_t *info, void *context)
{
    sig_log("SIGILL\n");
    raise(SIGKILL);
}

void segfault_handler(int sig, siginfo_t *info, void *context)
{
    sig_log("SIGSEGV\n");
    raise(SIGKILL);
}

void setup_signal()
{
    struct sigaction sa;
    sigemptyset(&sa.sa_mask);

    // SIGTRAP handler
    sa.sa_sigaction = trap_handler;
    sa.sa_flags = SA_SIGINFO | SA_NODEFER;
    sigaction(SIGTRAP, &sa, NULL);

    // SIGSEGV handler
    sa.sa_sigaction = segfault_handler;
    sa.sa_flags = SA_SIGINFO | SA_NODEFER;
    sigaction(SIGSEGV, &sa, NULL);

    // SIGILL
    sa.sa_sigaction = illegal_instruction_handler;
    sa.sa_flags = SA_SIGINFO | SA_NODEFER;
    sigaction(SIGILL, &sa, NULL);
}

/* ------------------------------------------------------------------ */
/* Shared memory setup                                                */
/* ------------------------------------------------------------------ */

void setup_shm(void)
{
    const char *env = getenv(SHM_ID);
    if (env == NULL)
    {
        char msg[256];
        snprintf(msg, sizeof(msg), "%s not set\n", SHM_ID);
        log_line(msg);
        exit(EXIT_FAILURE);
    }

    errno = 0;
    char *endptr = NULL;
    long id = strtol(env, &endptr, 10);
    if (errno != 0 || endptr == env || *endptr != '\0' || id < 0)
    {
        char msg[256];
        snprintf(msg, sizeof(msg), "invalid %s value: %s\n", SHM_ID, env);
        log_line(msg);
        exit(EXIT_FAILURE);
    }

    addresses = (Trace *)shmat((int)id, NULL, 0);
    if (addresses == (Trace *)-1)
    {
        log_line("shmat error\n");
        exit(EXIT_FAILURE);
    }

    const char *trace_env = getenv(SHM_ENV_VAR);
    if (trace_env == NULL)
    {
        char msg[256];
        snprintf(msg, sizeof(msg), "%s not set\n", SHM_ENV_VAR);
        log_line(msg);
        exit(EXIT_FAILURE);
    }

    errno = 0;
    endptr = NULL;
    long trace_id = strtol(trace_env, &endptr, 10);
    if (errno != 0 || endptr == trace_env || *endptr != '\0' || trace_id < 0)
    {
        char msg[256];
        snprintf(msg, sizeof(msg), "invalid %s value: %s\n", SHM_ENV_VAR, env);
        log_line(msg);
        exit(EXIT_FAILURE);
    }

    trace_bits = (u8 *)shmat((int)trace_id, NULL, 0);
    if (trace_bits == (u8 *)-1)
    {
        log_line("shmat error\n");
        exit(EXIT_FAILURE);
    }
}

/* ------------------------------------------------------------------ */
/* Entry point                                                        */
/* ------------------------------------------------------------------ */

int main(int argc, char **argv)
{
    if (argc < 2)
    {
        log_line("usage: harness <input_file>\n");
        exit(EXIT_FAILURE);
    }
    if (argc >= 3 && strcmp(argv[2], "check") == 0) {
        check = 1;
    }
    if (!check) {
        setup_shm();
    }
    setup_signal();
    log_line("starting target_main with input file: %s\n", argv[1]);
    char *args[] = {argv[0], argv[1], "/dev/null", NULL};
    int arg = sizeof(args) / sizeof(args[0]) - 1;
    int result = target_main(arg, args);
    if (check) {
        int my_count = 0;
        for (int i = 0; i < MAP_SIZE; i++) {
            if (count[i] > 0) {
                my_count++;
            }
        }
        log_line("Number of edges covered: %d\n", my_count);
    }
    return result;
}