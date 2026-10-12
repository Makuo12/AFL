// #define _GNU_SOURCE
// #include <errno.h>
// #include <malloc.h>
// #include <stddef.h>
// #include <stdint.h>
// #include <stdlib.h>
// #include <string.h>
// #include <unistd.h>

// /*
//  * Heap tracking by interposition.
//  *
//  * This file DEFINES malloc/free/calloc/realloc/memalign/... in the executable,
//  * so every caller in the process (the target, libc internals, libstdc++.so's
//  * operator new/delete) goes through it. That is what makes the bookkeeping
//  * complete: nothing can free a block behind the tracker's back.
//  *
//  * Tracking only starts at __untracer_heap_start(). Blocks allocated before
//  * that (harness setup, libc init) are never tracked and never freed.
//  * __untracer_heap_reset() frees every tracked block that is still live.
//  *
//  * The tracker's own memory comes from __libc_malloc / __libc_free, which are
//  * never interposed, so it can't recurse into itself.
//  */
// extern void *__libc_malloc(size_t size);
// extern void __libc_free(void *ptr);
// extern void *__libc_calloc(size_t n, size_t size);
// extern void *__libc_realloc(void *ptr, size_t size);
// extern void *__libc_memalign(size_t alignment, size_t size);

// #define uthash_malloc(sz) __libc_malloc(sz)
// #define uthash_free(ptr, sz) __libc_free(ptr)
// #include "uthash.h"
// #include "global.h"

// /* State must survive the global restore, so it lives in its own section. */
// #define KEEP __attribute__((section("untracer_state")))
// /* The build uses -fvisibility=hidden; these must be exported so libc and
//  * libstdc++.so resolve malloc/free to the versions defined here. */
// #define EXPORT __attribute__((visibility("default")))

// typedef struct heap_node
// {
//     void *ptr; /* hash key */
//     size_t size;
//     UT_hash_handle hh;
//     struct heap_node *free_next;
// } heap_node;

// static KEEP heap_node *heap_map = NULL;
// static KEEP heap_node *free_nodes = NULL;
// static KEEP int heap_enabled = 0;
// static KEEP int heap_paused = 0;

// /* ---- node pool (so tracking doesn't call malloc once per allocation) ---- */

// #define CHUNK_NODES 4096

// static heap_node *node_get(void)
// {
//     if (!free_nodes)
//     {
//         heap_node *chunk = (heap_node *)__libc_malloc(sizeof(heap_node) * CHUNK_NODES);
//         if (!chunk)
//             return NULL;
//         for (size_t i = 0; i < CHUNK_NODES; i++)
//         {
//             chunk[i].free_next = free_nodes;
//             free_nodes = &chunk[i];
//         }
//     }
//     heap_node *n = free_nodes;
//     free_nodes = n->free_next;
//     return n;
// }

// static void node_put(heap_node *n)
// {
//     n->free_next = free_nodes;
//     free_nodes = n;
// }

// /* ---- bookkeeping -------------------------------------------------------- */

// static heap_node *find_node(void *p)
// {
//     heap_node *n = NULL;
//     HASH_FIND_PTR(heap_map, &p, n);
//     return n;
// }

// /* Adds a node regardless of pause state. */
// static void add_node(void *p, size_t size)
// {
//     heap_node *n = find_node(p);
//     if (n)
//     {
//         n->size = size; /* stale entry for a reused address: refresh it */
//         return;
//     }
//     n = node_get();
//     if (!n)
//         return;
//     n->ptr = p;
//     n->size = size;
//     HASH_ADD_PTR(heap_map, ptr, n);
// }

// static void remove_node(heap_node *n)
// {
//     HASH_DEL(heap_map, n);
//     node_put(n);
// }

// /* New allocations are tracked only while enabled and not paused. */
// static void track(void *p, size_t size)
// {
//     if (p && heap_enabled && heap_paused == 0)
//         add_node(p, size);
// }

// /* ---- interposed allocator entry points --------------------------------- */

// EXPORT void *malloc(size_t size)
// {
//     void *p = __libc_malloc(size);
//     track(p, size);
//     return p;
// }

// EXPORT void free(void *p)
// {
//     if (!p)
//         return;
//     if (heap_enabled)
//     {
//         heap_node *n = find_node(p);
//         if (n)
//             remove_node(n);
//     }
//     __libc_free(p);
// }

// EXPORT void *calloc(size_t n, size_t size)
// {
//     void *p = __libc_calloc(n, size);
//     track(p, n * size);
//     return p;
// }

// EXPORT void *realloc(void *p, size_t size)
// {
//     if (p == NULL)
//         return malloc(size);
//     if (size == 0)
//     {
//         free(p); /* glibc frees the block and returns NULL */
//         return NULL;
//     }

//     heap_node *n = heap_enabled ? find_node(p) : NULL;
//     void *q = __libc_realloc(p, size);
//     if (!q)
//         return NULL; /* original block is untouched and stays tracked */

//     /* Blocks from before the baseline stay untracked even if they move. */
//     if (n)
//     {
//         if (q != p)
//         {
//             remove_node(n);
//             add_node(q, size);
//         }
//         else
//             n->size = size;
//     }
//     return q;
// }

// EXPORT void *memalign(size_t alignment, size_t size)
// {
//     void *p = __libc_memalign(alignment, size);
//     track(p, size);
//     return p;
// }

// EXPORT void *aligned_alloc(size_t alignment, size_t size)
// {
//     return memalign(alignment, size);
// }

// EXPORT int posix_memalign(void **out, size_t alignment, size_t size)
// {
//     if (alignment == 0 || (alignment & (alignment - 1)) != 0 ||
//         alignment % sizeof(void *) != 0)
//         return EINVAL;
//     void *p = __libc_memalign(alignment, size);
//     if (!p)
//         return ENOMEM;
//     *out = p;
//     track(p, size);
//     return 0;
// }

// EXPORT void *valloc(size_t size)
// {
//     return memalign((size_t)sysconf(_SC_PAGESIZE), size);
// }

// EXPORT void *pvalloc(size_t size)
// {
//     size_t page = (size_t)sysconf(_SC_PAGESIZE);
//     return memalign(page, (size + page - 1) & ~(page - 1));
// }

// /* ---- control API (see global.h) ---------------------------------------- */

// /* Start tracking. Call once, after harness setup and before the target runs. */
// void __untracer_heap_start(void)
// {
//     heap_enabled = 1;
// }

// /* New allocations made between pause and resume are NOT tracked, so harness
//  * code that runs during the target (e.g. the trap handler) can keep its memory
//  * across resets. Calls nest. */
// void __untracer_heap_pause(void)
// {
//     heap_paused++;
// }

// void __untracer_heap_resume(void)
// {
//     if (heap_paused > 0)
//         heap_paused--;
// }

// /* Frees every tracked block that is still live. Call after
//  * close_open_file_handles() and before __untracer_restore_global(). */
// void __untracer_heap_reset(void)
// {
//     if (!heap_enabled)
//         return;

//     heap_node *n, *tmp;
//     HASH_ITER(hh, heap_map, n, tmp)
//     {
//         __libc_free(n->ptr);
//         node_put(n);
//     }
//     HASH_CLEAR(hh, heap_map);
// }