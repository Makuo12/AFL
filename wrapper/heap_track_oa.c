#define _GNU_SOURCE
#include <errno.h>
#include <malloc.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include "global.h" /* also declares __real_malloc / __real_free */

/*
 * Tracks heap blocks allocated during one persistent iteration and frees
 * the survivors on reset.
 *
 * Link with:
 *   -Wl,--wrap=malloc -Wl,--wrap=calloc -Wl,--wrap=realloc -Wl,--wrap=free
 *   -Wl,--wrap=reallocarray -Wl,--wrap=memalign -Wl,--wrap=aligned_alloc
 *   -Wl,--wrap=posix_memalign -Wl,--wrap=valloc -Wl,--wrap=pvalloc
 *   -Wl,--wrap=strdup -Wl,--wrap=strndup
 *   -Wl,--wrap=getline -Wl,--wrap=getdelim
 *
 * Tracking structure: one flat array of pointers, open addressing with linear
 * probing and backward-shift deletion (no tombstones). A NULL slot is empty;
 * NULL is never tracked. No per-block nodes, no uthash.
 *
 *   - Load factor is kept <= 0.5, so probes stay short and always terminate.
 *   - The table grows by doubling and then persists across iterations, so the
 *     steady state has no allocation or rehashing at all.
 *   - Reset scans the table, stopping as soon as every live entry is freed.
 *     If the table is far bigger than recent iterations need, it is halved so
 *     the scan cost does not stay inflated by one unusually large input.
 *
 * Bookkeeping uses __real_calloc/__real_free only, so it never recurses into
 * the wrappers and is never tracked itself. This file must NOT go through
 * CloneGlobalsPass.
 */
#define KEEP __attribute__((section("untracer_state")))

void *__real_calloc(size_t a, size_t b);
void *__real_realloc(void *p, size_t n);
void *__real_memalign(size_t al, size_t n);
void *__real_aligned_alloc(size_t al, size_t n);
int __real_posix_memalign(void **out, size_t al, size_t n);
void *__real_valloc(size_t n);
void *__real_pvalloc(size_t n);
char *__real_strdup(const char *s);
char *__real_strndup(const char *s, size_t n);
ssize_t __real_getline(char **lp, size_t *n, FILE *f);
ssize_t __real_getdelim(char **lp, size_t *n, int d, FILE *f);

#define NOT_FOUND ((size_t)-1)
#define INIT_BITS 12 /* 4096 slots to start */
#define INIT_CAP ((size_t)1 << INIT_BITS)

static KEEP void **tab = NULL;      /* NULL entry = empty slot */
static KEEP size_t tab_cap = 0;     /* power of two */
static KEEP unsigned tab_shift = 0; /* 64 - log2(tab_cap) */
static KEEP size_t heap_live = 0;   /* tracked entries */
static KEEP size_t heap_hwm = 0;    /* peak heap_live since last reset */
static KEEP int heap_tracking = 0;  /* only track after the baseline point */

/* ---- table primitives ---------------------------------------------------- */

/* Fibonacci hashing: top bits of a multiply spread aligned pointers well. */
static inline size_t hash_ptr(void *p, unsigned shift)
{
    return (size_t)(((uint64_t)(uintptr_t)p * 0x9E3779B97F4A7C15ULL) >> shift);
}

static inline size_t tab_find(void *p)
{
    size_t mask = tab_cap - 1;
    size_t i = hash_ptr(p, tab_shift);
    for (;;)
    {
        void *k = tab[i];
        if (k == p)
            return i;
        if (k == NULL)
            return NOT_FOUND;
        i = (i + 1) & mask;
    }
}

/* Remove the entry at slot i and shift later cluster members back over it. */
static void tab_erase(size_t i)
{
    size_t mask = tab_cap - 1;
    size_t j = i;
    for (;;)
    {
        j = (j + 1) & mask;
        void *k = tab[j];
        if (k == NULL)
            break;
        size_t h = hash_ptr(k, tab_shift);
        /* k may fill the hole at i if its home slot h is not in (i, j]. */
        if (((j - h) & mask) >= ((j - i) & mask))
        {
            tab[i] = k;
            i = j;
        }
    }
    tab[i] = NULL;
    heap_live--;
}

static int tab_grow(void)
{
    size_t ncap = tab_cap << 1;
    unsigned nshift = tab_shift - 1;
    void **nt = (void **)__real_calloc(ncap, sizeof(void *));
    if (!nt)
        return 0;

    size_t nmask = ncap - 1;
    for (size_t i = 0; i < tab_cap; i++)
    {
        void *k = tab[i];
        if (!k)
            continue;
        size_t j = hash_ptr(k, nshift);
        while (nt[j])
            j = (j + 1) & nmask;
        nt[j] = k;
    }
    __real_free(tab);
    tab = nt;
    tab_cap = ncap;
    tab_shift = nshift;
    return 1;
}

/* ---- tracking ------------------------------------------------------------ */

static inline void track_heap(void *p)
{
    if (!heap_tracking || p == NULL)
        return;

    /* Keep load <= 0.5. If growth fails, skip tracking (the block survives). */
    if ((heap_live + 1) * 2 > tab_cap && !tab_grow())
        return;

    size_t mask = tab_cap - 1;
    size_t i = hash_ptr(p, tab_shift);
    for (;;)
    {
        void *k = tab[i];
        if (k == p) /* stale entry for a reused address: already tracked */
            return;
        if (k == NULL)
            break;
        i = (i + 1) & mask;
    }
    tab[i] = p;
    if (++heap_live > heap_hwm)
        heap_hwm = heap_live;
}

static inline int untrack_heap(void *p)
{
    if (!heap_live)
        return 0;
    size_t i = tab_find(p);
    if (i == NOT_FOUND)
        return 0;
    tab_erase(i);
    return 1;
}

/* ---- allocation wrappers ------------------------------------------------ */

void *__wrap_malloc(size_t n)
{
    void *p = __real_malloc(n);
    track_heap(p);
    return p;
}

void *__wrap_calloc(size_t a, size_t b)
{
    void *p = __real_calloc(a, b);
    track_heap(p);
    return p;
}

void *__wrap_memalign(size_t al, size_t n)
{
    void *p = __real_memalign(al, n);
    track_heap(p);
    return p;
}

void *__wrap_aligned_alloc(size_t al, size_t n)
{
    void *p = __real_aligned_alloc(al, n);
    track_heap(p);
    return p;
}

int __wrap_posix_memalign(void **out, size_t al, size_t n)
{
    int rc = __real_posix_memalign(out, al, n);
    if (rc == 0)
        track_heap(*out);
    return rc;
}

void *__wrap_valloc(size_t n)
{
    void *p = __real_valloc(n);
    track_heap(p);
    return p;
}

void *__wrap_pvalloc(size_t n)
{
    void *p = __real_pvalloc(n);
    track_heap(p);
    return p;
}

/* libc-internal malloc calls are not wrapped, so wrap these explicitly. */
char *__wrap_strdup(const char *s)
{
    char *p = __real_strdup(s);
    track_heap(p);
    return p;
}

char *__wrap_strndup(const char *s, size_t n)
{
    char *p = __real_strndup(s, n);
    track_heap(p);
    return p;
}

void __wrap_free(void *p)
{
    if (p == NULL)
        return;
    /* Nothing tracked (or tracking not started): skip the lookup. */
    if (heap_live)
    {
        size_t i = tab_find(p);
        if (i != NOT_FOUND)
            tab_erase(i);
    }
    __real_free(p);
}

void *__wrap_realloc(void *p, size_t n)
{
    if (p == NULL)
    {
        void *r = __real_realloc(NULL, n);
        track_heap(r);
        return r;
    }

    /* NOT_FOUND => block predates the baseline. The slot index stays valid
     * across __real_realloc because it does not touch our table. */
    size_t oi = heap_live ? tab_find(p) : NOT_FOUND;
    void *r = __real_realloc(p, n);

    if (r == NULL)
    {
        if (n == 0 && oi != NOT_FOUND) /* glibc: realloc(p, 0) frees p */
            tab_erase(oi);
        return NULL; /* on real failure p is still valid and still tracked */
    }
    if (r != p && oi != NOT_FOUND)
    {
        tab_erase(oi);
        track_heap(r);
    }
    /* Baseline block that moved: deliberately NOT tracked (it must survive). */
    return r;
}

void *__wrap_reallocarray(void *p, size_t a, size_t b)
{
    size_t total;
    if (__builtin_mul_overflow(a, b, &total))
    {
        errno = ENOMEM;
        return NULL;
    }
    return __wrap_realloc(p, total);
}

/* getline/getdelim realloc *lineptr inside libc, bypassing the wrappers. */
static ssize_t line_common(char **lp, ssize_t r, char *old)
{
    if (lp && *lp != old)
    {
        if (old == NULL)
            track_heap(*lp);
        else if (untrack_heap(old))
            track_heap(*lp);
    }
    return r;
}

ssize_t __wrap_getdelim(char **lp, size_t *n, int d, FILE *f)
{
    char *old = lp ? *lp : NULL;
    return line_common(lp, __real_getdelim(lp, n, d, f), old);
}

ssize_t __wrap_getline(char **lp, size_t *n, FILE *f)
{
    char *old = lp ? *lp : NULL;
    return line_common(lp, __real_getline(lp, n, f), old);
}

/* ---- lifecycle ---------------------------------------------------------- */

/* Call once, right after __untracer_setup_global() / __untracer_snapshot_fds().
 * Everything allocated before this point is baseline and is never freed. */
void __untracer_heap_start(void)
{
    if (!tab)
    {
        tab = (void **)__real_calloc(INIT_CAP, sizeof(void *));
        if (!tab)
            abort();
        tab_cap = INIT_CAP;
        tab_shift = 64 - INIT_BITS;
    }
    heap_tracking = 1;
}

/* Call after close_open_file_handles() (streams may use tracked setvbuf
 * buffers) and before __untracer_restore_global(). */
void free_open_heap(void)
{
    size_t left = heap_live;
    for (size_t i = 0; left; i++) /* stop once every live entry is freed */
    {
        void *k = tab[i];
        if (k)
        {
            tab[i] = NULL;
            __real_free(k);
            left--;
        }
    }
    heap_live = 0;

    /* One huge input must not make every later reset scan a huge table. */
    if (tab_cap > INIT_CAP && heap_hwm * 8 < tab_cap)
    {
        size_t ncap = tab_cap >> 1;
        void **nt = (void **)__real_calloc(ncap, sizeof(void *));
        if (nt)
        {
            __real_free(tab);
            tab = nt;
            tab_cap = ncap;
            tab_shift++;
        }
    }
    heap_hwm = 0;
}