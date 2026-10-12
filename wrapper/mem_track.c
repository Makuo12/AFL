#define _GNU_SOURCE
#include <malloc.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <errno.h>
#include "global.h"

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
 * Bookkeeping uses __real_malloc/__real_free only, so it never recurses into
 * the wrappers. uthash must be told to do the same (macros below, before the
 * include). This file must NOT go through CloneGlobalsPass.
 */
#define KEEP __attribute__((section("untracer_state")))

void *__real_malloc(size_t n);
void *__real_calloc(size_t a, size_t b);
void *__real_realloc(void *p, size_t n);
void __real_free(void *p);
void *__real_reallocarray(void *p, size_t a, size_t b);
void *__real_memalign(size_t al, size_t n);
void *__real_aligned_alloc(size_t al, size_t n);
int __real_posix_memalign(void **out, size_t al, size_t n);
void *__real_valloc(size_t n);
void *__real_pvalloc(size_t n);
char *__real_strdup(const char *s);
char *__real_strndup(const char *s, size_t n);
ssize_t __real_getline(char **lp, size_t *n, FILE *f);
ssize_t __real_getdelim(char **lp, size_t *n, int d, FILE *f);

#define uthash_malloc(sz) __real_malloc(sz)
#define uthash_free(ptr, sz) __real_free(ptr)
#include "uthash.h"
#include "global.h"

typedef struct
{
    void *p; /* hash key */
    UT_hash_handle hh;
} heap_obj;

static KEEP heap_obj *heap_map = NULL;
static KEEP int heap_tracking = 0; /* only track after the baseline point */

static heap_obj *find_heap(void *p)
{
    heap_obj *s = NULL;
    HASH_FIND_PTR(heap_map, &p, s);
    return s;
}

static void track_heap(void *p)
{
    if (!heap_tracking || p == NULL || find_heap(p) != NULL)
        return;

    __untracer_heap_pause();
    heap_obj *s = (heap_obj *)__real_malloc(sizeof(*s));
    if (s)
    {
        s->p = p;
        HASH_ADD_PTR(heap_map, p, s); /* may allocate the bucket table */
    }
    __untracer_heap_resume();
}

static void drop_node(heap_obj *s)
{
    HASH_DEL(heap_map, s);
    __real_free(s);
}

static int untrack_heap(void *p)
{
    heap_obj *s = find_heap(p);
    if (!s)
        return 0;
    drop_node(s);
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
    untrack_heap(p);
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

    heap_obj *old = find_heap(p); /* NULL => block predates the baseline */
    void *r = __real_realloc(p, n);

    if (r == NULL)
    {
        if (n == 0 && old) /* glibc: realloc(p, 0) frees p */
            drop_node(old);
        return NULL; /* on real failure p is still valid and still tracked */
    }
    if (r != p && old)
    {
        drop_node(old);
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
    heap_tracking = 1;
}

/* Call after close_open_file_handles() (streams may use tracked setvbuf
 * buffers) and before __untracer_restore_global(). */
void free_open_heap(void)
{
    heap_obj *s, *tmp;
    HASH_ITER(hh, heap_map, s, tmp)
    {
        HASH_DEL(heap_map, s);
        __real_free(s->p);
        __real_free(s);
    }
}