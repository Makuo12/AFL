#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <inttypes.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/shm.h>
#include <sys/ucontext.h>
#include <unistd.h>

/* Real allocator, used for state that must survive every reset. Declared
 * here in case the headers below don't; identical redeclarations are fine. */
extern void *__real_malloc(size_t sz);
extern void __real_free(void *ptr);

/* The writable-page table must survive every reset, so its nodes and bucket
 * table must come from the real allocator. Going through the wrapped malloc
 * would register them with the heap tracker, which frees them on reset and
 * leaves writable_pages dangling. These macros must precede the first
 * #include of uthash.h. */
#define uthash_malloc(sz) __real_malloc(sz)
#define uthash_free(ptr, sz) __real_free(ptr)
#include "uthash.h"
#include "data.h"
#include "global.h"
#include "config.h"
#ifdef __APPLE__
#include <mach-o/getsect.h>
#include <mach-o/dyld.h>
extern const struct mach_header_64 _mh_execute_header;
#endif

/* State in this section survives __untracer_restore_global(). */
#define KEEP __attribute__((section("untracer_state")))

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

extern int target_main(int argc, char **argv);
extern void __reset_loop_counters(void);

extern void __untracer_snapshot_fds(void); /* file-handle tracker */
extern void close_open_file_handles(void);
extern void __untracer_heap_start(void); /* heap tracker */
extern void free_open_heap(void);

void log_line(const char *fmt, ...); /* defined below */

typedef unsigned char u8;

uint32_t *virgin_bits;
uint32_t *trace_bits;

#define DEFAULT_LOG_PATH "./output/trap_handler.log"
static KEEP char log_path[4096] = DEFAULT_LOG_PATH;

static int meta_file_fd = -1;
static int loop_threshold_fd = -1;

typedef struct
{
    uintptr_t page;
    UT_hash_handle hh;
} writable_page;

KEEP writable_page *writable_pages = NULL;

/* ------------------------------------------------------------------ */
/* Logging                                                            */
/* ------------------------------------------------------------------ */

/* NOT safe to call from signal handlers (stdio + malloc). */
void log_line(const char *fmt, ...)
{
    FILE *log_file = fopen(log_path, "a");
    if (!log_file)
        log_file = stderr; /* fallback */

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
/* Meta / loop-threshold files (append-only, signal-safe)             */
/* ------------------------------------------------------------------ */

/* Async-signal-safe decimal formatter. Returns number of bytes written
 * (at most 11). Does not NUL-terminate. */
static size_t put_i32(char *dst, int32_t v)
{
    char tmp[12];
    size_t n = 0, len = 0;
    uint32_t u = v < 0 ? 0u - (uint32_t)v : (uint32_t)v;

    if (v < 0)
        dst[len++] = '-';
    do
    {
        tmp[n++] = (char)('0' + (u % 10));
        u /= 10;
    } while (u);
    while (n)
        dst[len++] = tmp[--n];
    return len;
}

/* Append "id\n" to the meta file: this id is fully de-instrumented
 * (an edge that was hit, or a loop that reached MAX_LOOP). */
static void meta_data_dump(int32_t meta_id)
{
    char buf[16];
    size_t n = put_i32(buf, meta_id);
    buf[n++] = '\n';
    if (write(meta_file_fd, buf, n) != (ssize_t)n)
        sig_log("meta write failed, id=", (uintptr_t)(uint32_t)meta_id);
}

/* Append "id,cmp_value\n" to the threshold file. Thresholds only grow, so
 * the de-instrumentation tool takes the max per id and then drops every id
 * that appears in the meta file. */
static void loop_threshold_write(int32_t meta_id, int32_t cmp_value)
{
    char buf[32];
    size_t n = put_i32(buf, meta_id);
    buf[n++] = ',';
    n += put_i32(buf + n, cmp_value);
    buf[n++] = '\n';
    if (write(loop_threshold_fd, buf, n) != (ssize_t)n)
        sig_log("threshold write failed, id=", (uintptr_t)(uint32_t)meta_id);
}

static void init_log_path(void)
{
    const char *p = getenv("LOG_FILE");
    if (p && *p && strlen(p) < sizeof(log_path))
    {
        strcpy(log_path, p);
    }
}

static int open_append_env(const char *env_name)
{
    const char *path = getenv(env_name);
    if (!path || strlen(path) < 2)
    {
        log_line("%s not set\n", env_name);
        exit(EXIT_FAILURE);
    }

    /* O_APPEND: every write lands at the end, even after a harness restart. */
    int fd = open(path, O_CREAT | O_WRONLY | O_APPEND, 0644);
    if (fd < 0)
    {
        log_line("cannot open %s (%s): %s\n", env_name, path, strerror(errno));
        exit(EXIT_FAILURE);
    }
    return fd;
}

static void setup_fd(void)
{
    loop_threshold_fd = open_append_env("LOOP_THRESHOLD_FILE");
    meta_file_fd = open_append_env("META_DATA_FILE");
}

/* ------------------------------------------------------------------ */
/* Code-page patching                                                 */
/* ------------------------------------------------------------------ */

void make_range_writable(uintptr_t start, uintptr_t end)
{
    static size_t page_size = 0;
    if (!page_size)
        page_size = (size_t)sysconf(_SC_PAGESIZE);

    uintptr_t page = start & ~(uintptr_t)(page_size - 1);
    uintptr_t last_page = (end + 4) & ~(uintptr_t)(page_size - 1); /* cover end..end+4 too */

    for (; page <= last_page; page += page_size)
    {
        writable_page *found;
        HASH_FIND(hh, writable_pages, &page, sizeof(uintptr_t), found);

        if (found)
            continue; /* already writable - skip the syscall */

        if (mprotect((void *)page, page_size, PROT_READ | PROT_WRITE | PROT_EXEC) != 0)
        {
            sig_log("mprotect failed, page=", page);
            _exit(EXIT_FAILURE);
        }

        /* __real_malloc via the uthash macros above: untracked, persistent. */
        writable_page *entry = (writable_page *)__real_malloc(sizeof(*entry));
        if (entry)
        {
            entry->page = page;
            HASH_ADD(hh, writable_pages, page, sizeof(uintptr_t), entry);
        }
    }
}

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
    (void)sig;
    (void)info;
    ucontext_t *uc = (ucontext_t *)ctx;
    uintptr_t rip = (uintptr_t)UC_PC(uc);
    uintptr_t addr = rip - 1;

    if (addr < 0x400000)
    {
        sig_log("addr underflow, base address assumption wrong: ", addr);
        raise(SIGKILL);
        return;
    }

    make_range_writable(addr - 7, addr + 9);

    uintptr_t resume_addr = 0;
    unsigned char *trap = (unsigned char *)addr;
    int32_t value = 0, new_value = 0, index_block = 0;
    int32_t bucket_value = 0;
    /* Loop-counter layout:  0xcc 0x90 0x90 0x90 0x90 id0 id1 id2 id3   (9 bytes)
     * Edge-counter layout:  0xcc id0 id1 id2 id3                       (5 bytes) */
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
            /* Retired: strip the instrumentation. Only the meta file gets a
             * line; the de-instrumentation tool drops this id's threshold. */
            memset(trap, 0x90, 9);
            resume_addr = addr + 9;
            meta_data_dump(index_block);
        }
        else
        {
            memcpy((void *)num_addr, &new_value, sizeof(new_value));
            resume_addr = cmp_addr;
            loop_threshold_write(index_block, new_value);
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
        meta_data_dump(index_block);
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
    (void)info;
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
    raise(SIGKILL);
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

    /* SIGTRAP handler */
    sa.sa_sigaction = trap_handler;
    sa.sa_flags = SA_SIGINFO | SA_NODEFER;
    sigaction(SIGTRAP, &sa, NULL);

    /* Crash handlers: run on the alternate stack, and a fault inside the
     * handler itself falls through to the default action instead of recursing. */
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

static void run_persistent(char *argv0, char *input)
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
        __reset_loop_counters();
        optind = 0; /* make getopt in target_main restart */
        target_main(3, args);

        /* Reset order matters:
         *  1. close files first (fclose needs the heap blocks it owns),
         *  2. then free the heap blocks the target left behind,
         *  3. then restore the globals that pointed at them. */
        close_open_file_handles();
        free_open_heap();
        __untracer_restore_global();

        if (standalone)
            exit(0);

        uint32_t status = 0; /* must be 0 */
        if (write(FORKSRV_FD + 1, &status, 4) != 4)
            _exit(0);
    }
}

int main(int argc, char **argv)
{
    init_log_path();
    if (argc < 2)
    {
        log_line("usage: harness <input_file>\n");
        exit(EXIT_FAILURE);
    }
    setup_fd();

    /* Static stdout buffer, so stdout never points into a heap block that the
     * tracker could free. Under --wrap, libc's own lazily allocated buffer is
     * not tracked anyway, so this is a cheap safeguard rather than a must. */
    static KEEP char stdout_buf[BUFSIZ];
    setvbuf(stdout, stdout_buf, _IOFBF, sizeof(stdout_buf));

    setup_shm();
    setup_signal();
    __untracer_setup_global(); /* globals snapshot */
    __untracer_snapshot_fds(); /* fd baseline */
    __untracer_heap_start();   /* from here on the heap tracker records */
    run_persistent(argv[0], argv[1]);
    return 0;
}