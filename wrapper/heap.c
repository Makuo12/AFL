#include <stdio.h>
#include <stdlib.h>
#include "uthash.h"
#include "global.h"

/* NOTE: this file must call the REAL malloc/calloc/realloc/free.
 * Make sure global.h does not #define malloc -> myMalloc (etc.),
 * or the tracking code below would recurse forever. */

typedef struct
{
    void *key;         /* the tracked heap pointer (hash key) */
    UT_hash_handle hh; /* makes this structure hashable */
} ptr_obj;

static ptr_obj *ptr_map = NULL;

static ptr_obj *find_ptr(void *ptr)
{
    ptr_obj *s = NULL;
    /* HASH_FIND_PTR takes the ADDRESS of the key value */
    HASH_FIND_PTR(ptr_map, &ptr, s);
    return s;
}

/* Track a pointer. Ignores NULL and pointers that are already tracked
 * (uthash does not check for duplicate keys, and a duplicate would make
 * a later delete leave a stale entry behind). */
static void add_ptr(void *ptr)
{
    if (ptr == NULL || find_ptr(ptr) != NULL)
        return;

    ptr_obj *s = (ptr_obj *)malloc(sizeof(*s));
    if (s == NULL)
        return; /* can't track it; it just won't be auto-freed */

    s->key = ptr;
    HASH_ADD_PTR(ptr_map, key, s);
}

static void delete_ptr(ptr_obj *obj)
{
    if (obj != NULL)
    {
        HASH_DEL(ptr_map, obj);
        free(obj);
    }
}

void *myMalloc(size_t size)
{
    void *tmp = malloc(size);
    add_ptr(tmp); /* ignores NULL */
    return tmp;
}

void *myCalloc(size_t nmemb, size_t size)
{
    void *tmp = calloc(nmemb, size);
    add_ptr(tmp);
    return tmp;
}

void *myRealloc(void *ptr, size_t size)
{
    void *tmp = realloc(ptr, size);

    /* Failure with size != 0: the old block is still valid and must stay
     * tracked, otherwise it would leak out of free_ptrs(). */
    if (tmp == NULL && size != 0)
        return NULL;

    /* Success (or realloc(ptr, 0), which frees ptr): drop the old entry. */
    if (ptr != NULL)
        delete_ptr(find_ptr(ptr));

    add_ptr(tmp); /* ignores NULL */
    return tmp;
}

void myFree(void *ptr)
{
    if (ptr == NULL)
        return;
    delete_ptr(find_ptr(ptr));
    free(ptr);
}

/* Free everything the target allocated and never freed. */
void free_ptrs(void)
{
    ptr_obj *s, *tmp;
    HASH_ITER(hh, ptr_map, s, tmp)
    {
        free(s->key);
        delete_ptr(s); /* HASH_ITER saved the next pointer in tmp */
    }
}