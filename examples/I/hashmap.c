#include <string.h>

#include "hashmap.h"

struct hashmap
{
    int size;
    struct hashmap_alloc alloc;
    struct hashmap_keyval* buckets[];
};

struct hashmap_keyval
{
    char* key;
    void* val;
    struct hashmap_keyval* next;
};

/* Very simple hash function */
static int hash_func(char* key, size_t key_len)
{
    int hash = key_len;
    size_t i;

    for (i = 0; i < key_len; i++) {
        hash ^= (int)key[i];
    }

    return hash;
}

struct hashmap* hashmap_new(int size, struct hashmap_alloc alloc)
{
    int i;

    /* Use user provided allocator */
    struct hashmap* hashmap = alloc.malloc(sizeof(struct hashmap) +
        (sizeof(struct hashmap_keyval) * size));

    hashmap->size = size;
    hashmap->alloc = alloc;
    for (i = 0; i < size; i++) {
        hashmap->buckets[i] = NULL;
    }

    return hashmap;
}

void hashmap_delete(struct hashmap* hashmap)
{
    if (hashmap == NULL) {
        return;
    }

    int i;
    for (i = 0; i < hashmap->size; i++) {
        for (struct hashmap_keyval *iter = hashmap->buckets[i]; iter != NULL;
            iter = iter->next)
        {
            hashmap->alloc.free(iter);
        }
    }

    hashmap->alloc.free(hashmap);
}

struct hashmap_keyval* hashmap_set(struct hashmap* hashmap, char* key,
    size_t key_len, void* val)
{
    if (hashmap == NULL) {
        return NULL;
    }

    int hash = hash_func(key, key_len);
    hash = hash % hashmap->size;

    /* Check if this is the first item in the bucket. */
    if (hashmap->buckets[hash] == NULL) {
        struct hashmap_keyval* keyval = 
            hashmap->alloc.malloc(sizeof(struct hashmap_keyval));
        keyval->key = key;
        keyval->val = val;
        keyval->next = NULL;
        hashmap->buckets[hash] = keyval;
        return keyval;
    }

    struct hashmap_keyval** iter = &hashmap->buckets[hash];
    while (*iter) {
        /* Check if the given key exists */
        if (strcmp((*iter)->key, key) == 0) {
            /* If so, update the value */
            (*iter)->val = val;
            return *iter;
        }
        iter = &(*iter)->next;
    }

    /* Add new value to the end of the bucket */
    *iter = hashmap->alloc.malloc(sizeof(struct hashmap_keyval));
    (*iter)->key = key;
    (*iter)->val = val;
    (*iter)->next = NULL;
    return *iter;
}

void* hashmap_get(struct hashmap* hashmap, char* key, size_t key_len)
{
    int hash = hash_func(key, key_len);
    hash = hash % hashmap->size;

    if (hashmap->buckets[hash] == NULL) {
        return NULL;
    }

    struct hashmap_keyval* iter = hashmap->buckets[hash];
    while (iter) {
        /* Check if the given key exists */
        if (strcmp(iter->key, key) == 0) {
            break;
        }
        iter = iter->next;
    }

    return iter ? iter->val : NULL;
}
