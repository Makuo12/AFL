#include <stdio.h>
#include <stdlib.h>
#include "uthash.h"
#include "global.h"

typedef struct
{
    FILE *f;                                               /* we'll use this field as the key */
    int i;                                                 /* this field is for the hashed object */
    UT_hash_handle hh; /* makes this structure hashable */ // IDK how this works, they just said it does and it did
} file_ptr_obj;

file_ptr_obj *file_ptr_map = NULL;

void add_file_ptr(FILE *key_ptr)
{
    file_ptr_obj *s;

    s = (file_ptr_obj *)malloc(sizeof(file_ptr_obj));
    s->f = key_ptr;
    s->i = 1;
    HASH_ADD_PTR(file_ptr_map, f, s); /* id: name of key field!!! LOOK MORE INTO THIS, REPLACE WITH THE CORRECT
                                      FUNCTION FOR ADDING A VOID POINTER AND THEN RECREATE WITH FIND */
}

// Responsible for finding the pointer to confirm that
file_ptr_obj *find_file_ptr(FILE *ptr_id)
{
    file_ptr_obj *s;

    HASH_FIND_PTR(file_ptr_map, &ptr_id,
                  s); // Change to the correct function for storing a void pointer, maybe this can be simplified.
    return s;
}

// Deletes the pointer object from the hash table
void delete_file_ptr(file_ptr_obj *obj)
{
    if (obj != NULL)
    {
        HASH_DEL(file_ptr_map, obj);
        free(obj);
    }
}

FILE *fopen_hook(const char *pathname, const char *mode)
{
    FILE *f = fopen(pathname, mode);
    add_file_ptr(f);
    return f;
}

int fclose_hook(FILE *f)
{
    file_ptr_obj *p = find_file_ptr(f);
    int ret = fclose(f);
    delete_file_ptr(p);
    return ret;
}

void close_open_file_handles(void)
{
    file_ptr_obj *s, *tmp;
    HASH_ITER(hh, file_ptr_map, s, tmp)
    {
        fclose(s->f);
        delete_file_ptr(s);
    }
}