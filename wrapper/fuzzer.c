#define _GNU_SOURCE
#include <getopt.h>
#include <sys/ucontext.h>
#include <errno.h>
#include <inttypes.h>
#include <stdarg.h> /* va_list, used by log_line() in startup.c */
#include <signal.h>
#include <sys/mman.h>
#include <sys/shm.h>
#include <setjmp.h>
#include <getopt.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include "uthash.h"
#include "data.h"
#include "global.h"
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

uint32_t *virgin_bits;
uint32_t *trace_bits;

sigjmp_buf env;

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


static inline void record_hit(int32_t idx, uint32_t val, int is_loop)
{
    if (idx < 0 || idx >= MAP_SIZE)
    {
        log_line("trap index out of range: %d\n", idx);
        raise(SIGKILL);
    }
    uint32_t old = virgin_bits[idx];
    if (val <= old)
        return; /* already known (also after a harness restart) */
    virgin_bits[idx] = val;
    if (old == 0 && !is_loop)
        trace_bits[0]++; /* new edge */
    else
        trace_bits[3]++; /* new or higher loop bucket */
}

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
        log_line("addr underflow, base address assumption wrong\n");
        raise(SIGKILL);
        return;
    }

    off_t addr_offset = addr - 0x400000;
    (void)addr_offset; /* only used in the error branch below */

    make_range_writable(addr - 7, addr + 9);

    uintptr_t resume_addr = 0;
    unsigned char *trap = (unsigned char *)addr;
    int32_t value = 0, new_value = 0, index_block = 0;
    int32_t bucket_value = 0;
    // Loop-counter layout:  0xcc 0x90 0x90 0x90 0x90 id0 id1 id2 id3   (9 bytes)
    // Edge-counter layout:  0xcc id0 id1 id2 id3                       (5 bytes)
    if (*trap == 0xcc && trap[1] == 0x90 && trap[2] == 0x90 && trap[3] == 0x90 && trap[4] == 0x90)
    {
        uintptr_t cmp_addr = addr - 7;
        uintptr_t num_addr = cmp_addr + 1;
        memcpy(&value, (void *)num_addr, sizeof(value));
        if (value <= 1)
            new_value = 2;
        else if (value < LOOP_START_ADD)
            new_value = value + BUCKET_SMALL_INC;
        else
            new_value = value * MULTI_INC;

        memcpy(&index_block, (void *)(addr + 5), sizeof(index_block));
        if (new_value >= MAX_LOOP)
        {
            memset(trap, 0x90, 9);
            resume_addr = addr + 9;
        }
        else
        {
            memcpy((void *)num_addr, &new_value, sizeof(new_value));
            resume_addr = cmp_addr;
        }

        if (new_value <= LOOP_START_ADD)
            bucket_value = (new_value / 2) - 1;
        else
            for (uint32_t v = (uint32_t)new_value; v >= 4; v >>= 2)
                bucket_value++; /* floor(log4(new_value)), no libm */

        record_hit(index_block, (uint32_t)bucket_value + 1, 1);
    }
    else if (*trap == 0xcc)
    {
        memcpy(&index_block, (void *)(addr + 1), sizeof(index_block));
        memset(trap, 0x90, 5);
        resume_addr = addr + 5;
        record_hit(index_block, 1, 0);
    }
    else
    {
        log_line("failed at addr=%p offset=0x%llx\n",
                 (void *)addr, (unsigned long long)addr_offset);
        exit(EXIT_FAILURE);
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

void crash_handler(int sig, siginfo_t *info, void *ctx)
{
    ucontext_t *uc = (ucontext_t *)ctx;
#ifdef __linux__
    uintptr_t rip = uc->uc_mcontext.gregs[REG_RIP];
#elif defined(__APPLE__) && defined(__x86_64__)
    uintptr_t rip = uc->uc_mcontext->__ss.__rip;
#elif defined(__APPLE__) && defined(__aarch64__)
    uintptr_t rip = uc->uc_mcontext->__ss.__pc;
#endif
    if (trace_bits)
    {
        /* Outside the main image (libc etc.) the address moves with ASLR,
           so keep only the page offset, which is stable. */
        if (rip < 0x400000 || rip > 0x10000000)
            rip &= 0xfff;
        trace_bits[1] = (uint32_t)rip;
        trace_bits[2] = (uint32_t)sig;
    }
    log_line("fatal signal %lx\n", rip);
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

    int sigs[] = {SIGSEGV, SIGILL, SIGBUS, SIGFPE, SIGABRT};
    sa.sa_sigaction = crash_handler;
    sa.sa_flags = SA_SIGINFO | SA_NODEFER;
    for (unsigned i = 0; i < sizeof(sigs) / sizeof(sigs[0]); i++)
        sigaction(sigs[i], &sa, NULL);
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

    virgin_bits = (uint32_t *)shmat((int)id, NULL, 0);
    if (virgin_bits == (uint32_t *)-1)
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

    trace_bits = (uint32_t *)shmat((int)trace_id, NULL, 0);

    if (trace_bits == (uint32_t *)-1)
    {
        log_line("shmat error\n");
        exit(EXIT_FAILURE);
    }
}

void clean_up()
{
    close_open_file_handles();
    free_ptrs();
    int result = __untracer_restore_global();
    if (result < 0)
    {
        log_line("Global section restoration failed in clean_up().");
        exit(EXIT_FAILURE);
    }
}

void exitHook(int status)
{
    siglongjmp(env, -1);
}

static void run_persistent(char *argv0, char *input)
{
    uint32_t msg = 0;

    /* If fd 199 isn't open we're not under afl-fuzz: run once and exit. */
    int standalone = (write(FORKSRV_FD + 1, &msg, 4) != 4);
    char *args[] = {argv0, input, "/dev/null", NULL};
    for (;;)
    {
        if (!standalone)
        {
            uint32_t cmd;
            if (read(FORKSRV_FD, &cmd, 4) != 4)
                _exit(0);
            uint32_t pid = getpid(); /* see point 3 */
            if (write(FORKSRV_FD + 1, &pid, 4) != 4)
                _exit(0);
        }

        int r = sigsetjmp(env, 1);
        if (r > 0)
            _exit(0); /* crash path, handle later */
        if (r == 0)
        {
            optind = 0;
            target_main(3, args);
        }
        /* r == 0: returned normally. r < 0: exitHook fired. Same cleanup. */
        // clean_up();

        if (standalone)
            exit(0);

        uint32_t status = 0;
        if (write(FORKSRV_FD + 1, &status, 4) != 4)
            _exit(0);
    }
}

int main(int argc, char **argv)
{
    if (argc < 2)
    {
        log_line("usage: harness <input_file>\n");
        exit(EXIT_FAILURE);
    }
    setup_shm();
    setup_signal();
    __untracer_setup_global();
    run_persistent(argv[0], argv[1]);
    return 0;
}