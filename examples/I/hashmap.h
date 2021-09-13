#include <stddef.h>

struct hashmap;
struct hashmap_keyval;

struct hashmap_alloc {
    void*(*malloc)(size_t size);
    void(*free)(void* ptr);
};

struct hashmap* hashmap_new(int size, struct hashmap_alloc alloc);
void hashmap_delete(struct hashmap* hashmap);

struct hashmap_keyval* hashmap_set(struct hashmap* hashmap, char* key,
    size_t key_len, void* val);
void* hashmap_get(struct hashmap* hashmap, char* key, size_t key_len);
