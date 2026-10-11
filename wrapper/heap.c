#include <stdio.h>
#include <stdlib.h>
#include "uthash.h"
#include "global.h"

typedef struct
{
    void *key;                                             /* we'll use this field as the key */
    int i;                                                 /* this field is for the hashed object */
    UT_hash_handle hh; /* makes this structure hashable */ // IDK how this works, they just said it does and it did
} ptr_obj;

ptr_obj *ptr_map = NULL;

void add_ptr(void *key_ptr)
{
    ptr_obj *s;

    s = (ptr_obj *)malloc(sizeof(ptr_obj));
    s->key = key_ptr;
    s->i = 1;
    HASH_ADD_PTR(ptr_map, key, s); /* id: name of key field!!! LOOK MORE INTO THIS, REPLACE WITH THE CORRECT FUNCTION
                                      FOR ADDING A VOID POINTER AND THEN RECREATE WITH FIND */
}

// Responsible for finding the pointer to confirm that
ptr_obj *find_ptr(void *ptr_id)
{
    ptr_obj *s;

    HASH_FIND_PTR(ptr_map, &ptr_id, s); // Change to the correct function for storing a void pointer, maybe this can be simplified.
    return s;
}

// Deletes the pointer object from the hash table
void delete_ptr(ptr_obj *obj)
{
    if (obj != NULL)
    {
        HASH_DEL(ptr_map, obj);
        free(obj);
    }
}

/*
 * myMalloc is a stub function for malloc which stores the returned void type pointer
 * inside of an array to be deallocated in the event that free is never called
 */
void *myMalloc(size_t size)
{
    void *tmp = malloc(size);
    add_ptr(tmp);
    return tmp;
}

/*
 * myCalloc is a stub function for malloc which stores the returned void type pointer
 * inside of an array to be deallocated in the event that free is never called
 */
void *myCalloc(size_t nmemb, size_t size)
{
    void *tmp = calloc(nmemb, size);
    if (tmp != NULL)
    {
        add_ptr(tmp);
    }
    return tmp;
}

/*
 * myRealloc is a stub function for malloc which stores the returned void type pointer
 * inside of an array to be deallocated in the event that free is never called
 */
void *myRealloc(void *ptr, size_t size)
{
    void *tmp = realloc(ptr, size);
    if (ptr != NULL)
    {
        ptr_obj *p = find_ptr(ptr);
        delete_ptr(p);
    }
    if (tmp != NULL && size != 0)
    {
        add_ptr(tmp);
    }
    return tmp;
}

/*
 * My Free is a stub function for free which removes the pointer
 * from the array of void pointers and then frees the passed in
 * pointer
 */
void myFree(void *ptr)
{
    ptr_obj *p = find_ptr(ptr);
    free(ptr);
    delete_ptr(p);
}

void free_ptrs(void)
{
    ptr_obj *s, *tmp;
    HASH_ITER(hh, ptr_map, s, tmp)
    {
        free(s->key);
        delete_ptr(s);
    }
}