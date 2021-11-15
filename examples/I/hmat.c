#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <memkind.h>

#include "hashmap.h"

/* In this example, we'll use simple data base entries */
struct db_data {
    char* name;
    size_t name_len;
    void* data;
};

/* Single-argument wrappers for Memkind's malloc and free */
void* lowest_latency_malloc(size_t size)
{
    return memkind_malloc(MEMKIND_LOWEST_LATENCY_LOCAL, size);
}

void lowest_latency_free(void* ptr)
{
    memkind_free(MEMKIND_LOWEST_LATENCY_LOCAL, ptr);
}

void* highest_capacity_malloc(size_t size)
{
    return memkind_malloc(MEMKIND_HIGHEST_CAPACITY, size);
}

void highest_capacity_free(void* ptr)
{
    memkind_free(MEMKIND_HIGHEST_CAPACITY, ptr);
}

int main(void)
{
    const int DB_SIZE = 100;
    const int KEY_SIZE = 16;
    const int DATA_SIZE = 10 * 1024;
    const int BUCKETS_NUM = 100;
    int i;

    /* Hashmap structure used in this example allows user to define custom
     * allocator for buckets and bucket entires. Because we want insert and
     * get operation to be fast, we use functions that uses Memkind's
     * MEMKIND_LOWEST_LATENCY kind.
     */
    struct hashmap_alloc lowest_latency_allocator = {lowest_latency_malloc,
        lowest_latency_free};

    /* Create a hashmap - all malloc/free operations (including allocating
     * hashmap itself) will use our lowest latency allocator.
     */
    struct hashmap* hm = hashmap_new(BUCKETS_NUM,
        lowest_latency_allocator);

    /* Create a data base - here the speed of data access is less important than
     * ability to store large num of entires, so we use Memkind's
     * MEMKIND_HIGHEST_CAPACITY kind to store database itself and all entries'
     * data. Still, we want all hashmap operations on keys to be done with
     * highest speed, so we keep entires' keys on memory with lowest latency.
     */
    struct db_data* db = highest_capacity_malloc(sizeof(struct db_data) *
        DB_SIZE);

    for (i = 0; i < DB_SIZE; i++) {
        /* Store data in memory with highest capacity */
        db[i].data = highest_capacity_malloc(DATA_SIZE);

        /* Store keys in memory with lowest latency */
        db[i].name = lowest_latency_malloc(KEY_SIZE);
        size_t name_len = snprintf(db[i].name, KEY_SIZE, "item %d", i);
        db[i].name_len = name_len;

        /* Add current entry to hashmap */
        hashmap_set(hm, db[i].name, name_len, db[i].data);
    }

    /* Iterate over all entires in database and check if all of them were
     * correctly allocated. NOTE: all memory accesses in this loop are done on
     * memory with lowest latency.
     */
    for (i = 0; i < DB_SIZE; i++) {
        if (hashmap_get(hm, db[i].name, db[i].name_len) != db[i].data) {
            fprintf(stderr, "ERROR: bad data at %d\n", i);
            exit(-1);
        }
    }

    /* Cleanup. Note that for freeing memory we could use generic Memkind free
     * function and pass NULL as kind - this way Memkind will figure out correct
     * kind by itself only by looking at the data pointer. */
    for (i = 0; i < DB_SIZE; i++) {
        memkind_free(NULL, db[i].data);
        memkind_free(NULL, db[i].name);
    }
    highest_capacity_free(db);

    hashmap_delete(hm);
    return 0;
}
