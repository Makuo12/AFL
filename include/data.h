#ifndef DATA_H_
#define DATA_H_
#include <sys/types.h> // Standard POSIX types
#include <inttypes.h>
typedef struct
{
    char d_name[1025];
    off_t st_size; // off_t is the standard POSIX type for file sizes
    char file_path[1025];
    int has_issues;
    int single_pass;
    int full_pass;
    int path_found;
    int trace_count;
} Entry;

typedef struct
{
    uintptr_t addr;
    int32_t cmp_value;
    int32_t index;
    int32_t is_edge_count;
} Trace;

#define LOOP_START_ADD_5 5
#define MAX_LOOP 1000
#define SHM_ID "SHM_ID"

typedef enum
{
    BLOCK,
    EDGE,
    EDGE_COUNT
} OracleType;

typedef struct
{
    int32_t meta_id;   /* key: trace.index */
    int32_t cmp_value; /* value: latest threshold written for this id */
    UT_hash_handle hh;
} LoopThresholdEntry;

extern LoopThresholdEntry *loop_threshold_map;
#endif