#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <inttypes.h>
#include <signal.h>
#include <stdarg.h> /* va_list, used by log_line() in startup.c */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <sys/shm.h>
#include <sys/ucontext.h>
#include <unistd.h>

/* The writable-page table must survive every reset, so its nodes and bucket
 * table must come from the real allocator. Going through the wrapped malloc
 * would register them with the heap tracker, which frees them on reset and
 * leaves writable_pages dangling. These macros must precede the first
 * #include of uthash.h. */
#include "uthash.h"
#include "data.h"
#include "config.h"
#ifdef __APPLE__
#include <mach-o/getsect.h>
#include <mach-o/dyld.h>
extern const struct mach_header_64 _mh_execute_header;
#endif


#if defined(__linux__)
#define UC_PC(uc) ((uc)->uc_mcontext.gregs[REG_RIP])
#elif defined(__APPLE__) && defined(__x86_64__)
#define UC_PC(uc) ((uc)->uc_mcontext->__ss.__rip)
#elif defined(__APPLE__) && defined(__aarch64__)
#define UC_PC(uc) ((uc)->uc_mcontext->__ss.__pc)
#else
#error "unsupported platform"
#endif

/* ------------------------------------------------------------------ */
/* Prototypes for externally-defined symbols                          */
/* ------------------------------------------------------------------ */

// extern void __reset_loop_counters(void);
extern int target_main(int argc, char **argv);
extern void __reset_loop_counters(void);

typedef unsigned char u8;

uint32_t *virgin_bits;
uint32_t *trace_bits;

typedef struct
{
    uintptr_t page;
    UT_hash_handle hh;
} writable_page;

writable_page *writable_pages = NULL;

#define DEFAULT_LOG_PATH "./output/trap_handler.log"
static char log_path[4096] = DEFAULT_LOG_PATH;

static void init_log_path(void)
{
    const char *p = getenv("LOG_FILE");
    if (p && *p && strlen(p) < sizeof(log_path))
    {
        strcpy(log_path, p);
    }
}

/* ------------------------------------------------------------------ */
/* Logging                                                            */
/* ------------------------------------------------------------------ */

/* NOT safe to call from signal handlers (stdio + malloc). */
void log_line(const char *fmt, ...)
{
    FILE *log_file = fopen(log_path, "a");
    if (!log_file)
        log_file = stderr; // fallback

    va_list ap;
    va_start(ap, fmt);
    vfprintf(log_file, fmt, ap);
    va_end(ap);

    if (log_file != stderr)
        fclose(log_file);
}

/* Async-signal-safe: only open/write/close, no stdio, no malloc. A crash
 * inside malloc or stdio would deadlock log_line() and show up as a hang
 * instead of a crash. Prints "<msg>0x<16 hex digits>\n". */
static void sig_log(const char *msg, uintptr_t val)
{
    static const char hex[] = "0123456789abcdef";
    char buf[96];
    size_t n = 0;

    while (*msg && n < 64)
        buf[n++] = *msg++;
    buf[n++] = '0';
    buf[n++] = 'x';
    for (int s = (int)(sizeof(val) * 8) - 4; s >= 0; s -= 4)
        buf[n++] = hex[(val >> s) & 0xf];
    buf[n++] = '\n';

    int fd = open(log_path, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd >= 0)
    {
        (void)!write(fd, buf, n);
        close(fd);
    }
    else
        (void)!write(2, buf, n);
}

/* ------------------------------------------------------------------ */
/* Code-page patching                                                 */
/* ------------------------------------------------------------------ */

// No more needed 
// void make_range_writable(uintptr_t start, uintptr_t end)
// {
//     static size_t page_size = 0;
//     if (!page_size)
//         page_size = (size_t)sysconf(_SC_PAGESIZE);

//     uintptr_t page = start & ~(uintptr_t)(page_size - 1);
//     uintptr_t last_page = (end + 4) & ~(uintptr_t)(page_size - 1); // cover end..end+4 too

//     for (; page <= last_page; page += page_size)
//     {
//         writable_page *found;
//         HASH_FIND(hh, writable_pages, &page, sizeof(uintptr_t), found);

//         if (found)
//             continue; /* already writable - skip the syscall */

//         if (mprotect((void *)page, page_size, PROT_READ | PROT_WRITE | PROT_EXEC) != 0)
//         {
//             sig_log("mprotect failed, page=", page);
//             _exit(EXIT_FAILURE);
//         }

//         writable_page *entry = (writable_page *)malloc(sizeof(*entry));
//         if (entry)
//         {
//             entry->page = page;
//             HASH_ADD(hh, writable_pages, page, sizeof(uintptr_t), entry);
//         }
//     }
// }

static inline void record_hit(int32_t idx, uint32_t val, int is_loop)
{
    if (idx < 0 || idx >= MAP_SIZE)
    {
        sig_log("trap index out of range: ", (uintptr_t)(uint32_t)idx);
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
    uintptr_t rip = (uintptr_t)UC_PC(uc);
    uintptr_t addr = rip - 1;

    if (addr < 0x400000)
    {
        sig_log("addr underflow, base address assumption wrong: ", addr);
        raise(SIGKILL);
        return;
    }

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
        sig_log("failed at addr=", addr);
        sig_log("            offset=", addr - 0x400000);
        _exit(EXIT_FAILURE);
    }

    UC_PC(uc) = resume_addr;
}

void crash_handler(int sig, siginfo_t *info, void *ctx)
{
    ucontext_t *uc = (ucontext_t *)ctx;
    uintptr_t rip = (uintptr_t)UC_PC(uc);

    if (trace_bits)
    {
        /* Outside the main image (libc etc.) the address moves with ASLR,
           so keep only the page offset, which is stable. */
        if (rip < 0x400000 || rip > 0x10000000)
            rip &= 0xfff;
        trace_bits[1] = (uint32_t)rip;
        trace_bits[2] = (uint32_t)sig;
    }
    sig_log("fatal signal, rip=", rip);
}

static char altstack[64 * 1024]; /* lets crash_handler run after a stack overflow */

void setup_signal(void)
{
    stack_t ss;
    ss.ss_sp = altstack;
    ss.ss_size = sizeof(altstack);
    ss.ss_flags = 0;
    sigaltstack(&ss, NULL);

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sigemptyset(&sa.sa_mask);

    // SIGTRAP handler
    sa.sa_sigaction = trap_handler;
    sa.sa_flags = SA_SIGINFO | SA_NODEFER;
    sigaction(SIGTRAP, &sa, NULL);

    // Crash handlers: run on the alternate stack, and a fault inside the
    // handler itself falls through to the default action instead of recursing.
    int sigs[] = {SIGSEGV, SIGILL, SIGBUS, SIGFPE, SIGABRT};
    sa.sa_sigaction = crash_handler;
    sa.sa_flags = SA_SIGINFO | SA_NODEFER | SA_ONSTACK | SA_RESETHAND;
    for (unsigned i = 0; i < sizeof(sigs) / sizeof(sigs[0]); i++)
        sigaction(sigs[i], &sa, NULL);
}

/* ------------------------------------------------------------------ */
/* Shared memory setup                                                */
/* ------------------------------------------------------------------ */

static uint32_t *attach_shm(const char *env_name)
{
    const char *env = getenv(env_name);
    if (env == NULL)
    {
        log_line("%s not set\n", env_name);
        exit(EXIT_FAILURE);
    }

    errno = 0;
    char *endptr = NULL;
    long id = strtol(env, &endptr, 10);
    if (errno != 0 || endptr == env || *endptr != '\0' || id < 0)
    {
        log_line("invalid %s value: %s\n", env_name, env);
        exit(EXIT_FAILURE);
    }

    void *p = shmat((int)id, NULL, 0);
    if (p == (void *)-1)
    {
        log_line("shmat error for %s: %s\n", env_name, strerror(errno));
        exit(EXIT_FAILURE);
    }
    return (uint32_t *)p;
}

void setup_shm(void)
{
    virgin_bits = attach_shm(SHM_ID);
    trace_bits = attach_shm(SHM_ENV_VAR);
}

/* ------------------------------------------------------------------ */
/* Persistent loop                                                    */
/* ------------------------------------------------------------------ */

static void run_forkserver(char *argv0, char *input)
{
    uint32_t msg = 0;

    /* If fd 199 isn't open we're not under afl-fuzz: run once and exit. */
    int standalone = (write(FORKSRV_FD + 1, &msg, 4) != 4);

    char devnull[] = "/dev/null"; /* writable, in case the target modifies argv */
    char *args[] = {argv0, input, devnull, NULL};

    for (;;)
    {
        if (!standalone)
        {
            uint32_t cmd;
            if (read(FORKSRV_FD, &cmd, 4) != 4)
                _exit(0); /* afl went away */
        }
        pid_t child = fork();
        if (child == 0)
        {
            __reset_loop_counters();
            optind = 0;
            int rc = target_main(3, args);
            _exit(rc);
        }
        else if (child < 0)
        {
            log_line("could not fork child");
            exit(EXIT_FAILURE);
        }

        int wait_status = 0;
        while (waitpid(child, &wait_status, 0) < 0)
        {
            if (errno != EINTR)
            {
                log_line("waitpid: %s\n", strerror(errno));
                _exit(1);
            }
        }

        if (WIFSIGNALED(wait_status))
            log_line("child %d killed by signal %d%s\n", child,
                    WTERMSIG(wait_status),
                    WCOREDUMP(wait_status) ? " (core dumped)" : "");
        else if (WIFEXITED(wait_status))
            log_line("child %d exited with code %d\n", child, WEXITSTATUS(wait_status));
        else
            log_line("child %d ended with unexpected status 0x%x\n", child, wait_status);

        if (standalone)
            exit(0);

        if (write(FORKSRV_FD + 1, &wait_status, 4) != 4)
            _exit(0);
    }
}

extern void *__start___traps[];
extern void *__stop___traps[];

typedef struct
{
    void *addr;
    uint32_t id;
    int is_loop;
} trap_entry;

static trap_entry *g_traps;
static size_t g_trap_count;

static void remap_page_shared(uintptr_t page_addr, long pg)
{
    int fd = memfd_create("text_shared", 0);
    if (fd < 0)
    {
        log_line("memfd_create failed for %p\n", (void *)page_addr);
        exit(EXIT_FAILURE);
    }

    if (ftruncate(fd, pg) != 0)
    {
        log_line("ftruncate failed for %p\n", (void *)page_addr);
        close(fd);
        exit(EXIT_FAILURE);
    }

    ssize_t written = write(fd, (void *)page_addr, pg);
    if (written != pg)
    {
        log_line("short write copying page %p (%zd/%ld)\n", (void *)page_addr, written, pg);
        close(fd);
        exit(EXIT_FAILURE);
    }

    void *r = mmap((void *)page_addr, pg, PROT_READ | PROT_WRITE | PROT_EXEC,
                   MAP_SHARED | MAP_FIXED, fd, 0);
    close(fd); // mapping holds its own reference; fd not needed after mmap

    if (r == MAP_FAILED)
    {
        log_line("mmap MAP_FIXED failed for %p\n", (void *)page_addr);
        exit(EXIT_FAILURE);
    }
}

static void make_pages_shared(void)
{
    long pg = sysconf(_SC_PAGESIZE);
    uintptr_t pgmask = ~(uintptr_t)(pg - 1);

    // Each trap's full on-disk span: 0xcc + 4 id bytes (category 0),
    // or 0xcc + 4 marker bytes + 4 id bytes (category 1, loop headers).
    // Any byte in that span may be overwritten for de-instrumentation,
    // so every page touched by the span — not just the page containing
    // the first byte — must be remapped shared.
    const uintptr_t span0 = 5; // 1 (0xcc) + 4 (id)
    const uintptr_t span1 = 9; // 1 (0xcc) + 4 (marker) + 4 (id)

    // Worst case: every trap touches 2 distinct pages (start + end).
    uintptr_t *pages = malloc(2 * g_trap_count * sizeof(uintptr_t));
    if (!pages)
    {
        log_line("make_pages_shared: oom\n");
        exit(EXIT_FAILURE);
    }

    size_t npages = 0;
    for (size_t i = 0; i < g_trap_count; i++)
    {
        uintptr_t start = (uintptr_t)g_traps[i].addr;
        uintptr_t span = g_traps[i].is_loop ? span1 : span0;
        uintptr_t end = start + span - 1; // last byte actually belonging to this trap

        uintptr_t base_start = start & pgmask;
        uintptr_t base_end = end & pgmask;

        // base_start is always needed; base_end only differs (and is only
        // needed) if the trap's tail bytes crossed into the next page.
        uintptr_t candidates[2] = {base_start, base_end};
        int ncand = (base_start == base_end) ? 1 : 2;

        for (int c = 0; c < ncand; c++)
        {
            uintptr_t base = candidates[c];
            int dup = 0;
            for (size_t j = 0; j < npages; j++)
            {
                if (pages[j] == base)
                {
                    dup = 1;
                    break;
                }
            }
            if (!dup)
                pages[npages++] = base;
        }
    }

    log_line("remapping %zu distinct pages (from %zu traps) as MAP_SHARED\n",
             npages, g_trap_count);

    for (size_t i = 0; i < npages; i++)
        remap_page_shared(pages[i], pg);

    free(pages);
}

static void collect_traps(void)
{
    size_t n = (size_t)(__stop___traps - __start___traps);
    g_traps = malloc(n * sizeof(trap_entry));
    if (!g_traps)
    {
        log_line("collect_traps: oom\n");
        exit(EXIT_FAILURE);
    }

    size_t kept = 0;
    for (size_t i = 0; i < n; i++)
    {
        void *addr = __start___traps[i];
        unsigned char *b = (unsigned char *)addr;

        int is_loop = (b[1] == 0x90 && b[2] == 0x90 &&
                       b[3] == 0x90 && b[4] == 0x90);
        uint32_t id = is_loop
                          ? (b[5] | (b[6] << 8) | (b[7] << 16) | (b[8] << 24))
                          : (b[1] | (b[2] << 8) | (b[3] << 16) | (b[4] << 24));

        g_traps[kept++] = (trap_entry){.addr = addr, .id = id, .is_loop = is_loop};
        log_line("trap[%zu]: addr=%p id=%u loop=%d\n",
                 i, g_traps[i].addr, g_traps[i].id, g_traps[i].is_loop);
    }
    g_trap_count = kept;
    log_line("collected %zu trap sites\n", g_trap_count);
}

int main(int argc, char **argv)
{
    init_log_path();
    if (argc < 2)
    {
        log_line("usage: harness <input_file>\n");
        exit(EXIT_FAILURE);
    }

    collect_traps();
    make_pages_shared(); // <-- add this

    setup_shm();
    setup_signal();
    run_forkserver(argv[0], argv[1]);
    return 0;
}