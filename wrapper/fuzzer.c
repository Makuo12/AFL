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
extern void __reset_loop_counters(void) __attribute__((weak));
void log_line(const char *fmt, ...);
static void sig_log(const char *msg, uintptr_t val);

typedef unsigned char u8;

uint32_t *virgin_bits;
uint32_t *trace_bits;

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

static int g_reset_loops = 0;

static void parse_coverage(const char *s)
{
    if (!strcmp(s, "all"))
        g_reset_loops = 1; /* only "all" resets loop counters */
    else if (!strcmp(s, "block") || !strcmp(s, "edge"))
        g_reset_loops = 0;
    else
    {
        log_line("unknown coverage type '%s' (use block|edge|all)\n", s);
        exit(EXIT_FAILURE);
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

static inline void record_hit(int32_t idx, uint32_t val, int is_loop)
{
    if (idx < 0 || idx >= MAP_SIZE)
    {
        sig_log("trap index out of range: ", (uintptr_t)(uint32_t)idx);
        abort();
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
        abort();
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
        abort();
    }

    UC_PC(uc) = resume_addr;
}


void setup_signal(void)
{

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sigemptyset(&sa.sa_mask);

    // SIGTRAP handler
    sa.sa_sigaction = trap_handler;
    sa.sa_flags = SA_SIGINFO | SA_NODEFER;
    sigaction(SIGTRAP, &sa, NULL);
}

/* ------------------------------------------------------------------ */
/* Shared memory setup                                                */
/* ------------------------------------------------------------------ */

static uint32_t *attach_shm(const char *env_name, size_t nwords)
{
    const char *env = getenv(env_name);
    if (env == NULL)
    {
        /* standalone replay: zero-filled map shared with the forked child */
        void *p = mmap(NULL, nwords * sizeof(uint32_t), PROT_READ | PROT_WRITE,
                       MAP_SHARED | MAP_ANONYMOUS, -1, 0);
        if (p == MAP_FAILED)
        {
            log_line("anon mmap failed for %s: %s\n", env_name, strerror(errno));
            exit(EXIT_FAILURE);
        }
        return (uint32_t *)p;
    }

    errno = 0;
    char *endptr = NULL;
    long id = strtol(env, &endptr, 10);
    if (errno != 0 || endptr == env || *endptr != '\0' || id < 0)
    {
        log_line("invalid %s value: %s\n", env_name, env);
        exit(EXIT_FAILURE);
    }

    struct shmid_ds ds;
    if (shmctl((int)id, IPC_STAT, &ds) == 0 && ds.shm_segsz < nwords * sizeof(uint32_t))
    {
        log_line("%s segment too small (%zu < %zu): fuzzer/harness built with different config.h?\n",
                 env_name, (size_t)ds.shm_segsz, nwords * sizeof(uint32_t));
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
    virgin_bits = attach_shm(SHM_ID, MAP_SIZE);
    trace_bits = attach_shm(SHM_ENV_VAR, MAP_SIZE_TRACE);
}

static void run_forkserver(char *argv0, char *input)
{
    uint32_t msg = 1;
    int standalone = !getenv(SHM_ENV_VAR) || write(FORKSRV_FD + 1, &msg, 4) != 4;

    char devnull[] = "/dev/null";
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
            close(FORKSRV_FD); /* don't hold afl's pipes open */
            close(FORKSRV_FD + 1);
            if (g_reset_loops && __reset_loop_counters)
                __reset_loop_counters();
            int rc = target_main(3, args);
            fflush(NULL);
            _exit(rc);
        }
        else if (child < 0)
        {
            log_line("could not fork child\n");
            _exit(1);
        }

        /* NEW: tell AFL the child's PID so it can kill it on timeout */
        if (!standalone)
        {
            if (write(FORKSRV_FD + 1, &child, 4) != 4)
                _exit(0);
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

        if (standalone)
        {
            if (WIFSIGNALED(wait_status))
                log_line("child killed by signal %d\n", WTERMSIG(wait_status));
            log_line("new edges=%u new loop buckets=%u\n", trace_bits[0], trace_bits[3]);
            exit(WIFEXITED(wait_status) ? WEXITSTATUS(wait_status) : 128 + WTERMSIG(wait_status));
        }

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

static int cmp_up(const void *a, const void *b)
{
    uintptr_t x = *(const uintptr_t *)a, y = *(const uintptr_t *)b;
    return (x > y) - (x < y);
}

/* pages[] must be sorted ascending and unique. */
static void remap_pages_shared(const uintptr_t *pages, size_t npages, long pg)
{
    if (npages == 0)
        return;

    int fd = memfd_create("text_shared", 0);
    if (fd < 0 || ftruncate(fd, (off_t)(npages * (size_t)pg)) != 0)
    {
        log_line("memfd setup failed: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }

    /* Copy all page contents first, while the originals are still mapped. */
    for (size_t i = 0; i < npages; i++)
    {
        if (pwrite(fd, (void *)pages[i], pg, (off_t)(i * (size_t)pg)) != pg)
        {
            log_line("pwrite failed for %p: %s\n", (void *)pages[i], strerror(errno));
            exit(EXIT_FAILURE);
        }
    }

    /* Map each run of address-adjacent pages with one mmap call. */
    for (size_t i = 0; i < npages;)
    {
        size_t j = i + 1;
        while (j < npages && pages[j] == pages[j - 1] + (uintptr_t)pg)
            j++;

        void *r = mmap((void *)pages[i], (j - i) * (size_t)pg,
                       PROT_READ | PROT_WRITE | PROT_EXEC,
                       MAP_SHARED | MAP_FIXED, fd, (off_t)(i * (size_t)pg));
        if (r == MAP_FAILED)
        {
            log_line("mmap MAP_FIXED failed for %p (%zu pages): %s\n",
                     (void *)pages[i], j - i, strerror(errno));
            exit(EXIT_FAILURE);
        }
        i = j;
    }
    close(fd); /* mappings hold their own reference */
}

static void make_pages_shared(void)
{
    long pg = sysconf(_SC_PAGESIZE);
    uintptr_t pgmask = ~(uintptr_t)(pg - 1);

    const uintptr_t span0 = 5; // 0xcc + 4 id bytes
    const uintptr_t span1 = 9; // 0xcc + 4 marker bytes + 4 id bytes

    uintptr_t *pages = malloc(2 * g_trap_count * sizeof(uintptr_t));
    if (!pages)
    {
        log_line("make_pages_shared: oom\n");
        exit(EXIT_FAILURE);
    }

    size_t n = 0;
    for (size_t i = 0; i < g_trap_count; i++)
    {
        uintptr_t addr = (uintptr_t)g_traps[i].addr;
        uintptr_t start = addr - (g_traps[i].is_loop ? 7 : 0);
        uintptr_t end = addr + (g_traps[i].is_loop ? span1 : span0) - 1;

        uintptr_t first = start & pgmask;
        uintptr_t last = end & pgmask;

        pages[n++] = first;
        if (last != first)
            pages[n++] = last;
    }

    /* Sort, then drop duplicates. */
    qsort(pages, n, sizeof(*pages), cmp_up);
    size_t u = 0;
    for (size_t i = 0; i < n; i++)
        if (u == 0 || pages[i] != pages[u - 1])
            pages[u++] = pages[i];

    remap_pages_shared(pages, u, pg);
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
                        ? (b[5] | (b[6] << 8) | (b[7] << 16) | ((uint32_t)b[8] << 24))
                        : (b[1] | (b[2] << 8) | (b[3] << 16) | ((uint32_t)b[4] << 24));

        g_traps[kept++] = (trap_entry){.addr = addr, .id = id, .is_loop = is_loop};
        // log_line("trap[%zu]: addr=%p id=%u loop=%d\n",
        //          i, g_traps[i].addr, g_traps[i].id, g_traps[i].is_loop);
    }
    g_trap_count = kept;
    // log_line("collected %zu trap sites\n", g_trap_count);
}

int main(int argc, char **argv)
{
    init_log_path();
    if (argc < 2)
    {
        log_line("usage: harness <input_file> [all|edge|loop]\n");
        exit(EXIT_FAILURE);
    }
    if (argc >= 3)
        parse_coverage(argv[2]);

    collect_traps();
    make_pages_shared(); // <-- add this

    setup_shm();
    setup_signal();
    run_forkserver(argv[0], argv[1]);
    return 0;
}