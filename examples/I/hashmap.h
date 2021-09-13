#include <stddef.h>

struct hashmap;
struct hashmap_keyval;
typedef void* value;

struct hashmap_alloc {
    void*(*malloc)(size_t size);
    void(*free)(void* ptr);
};

struct hashmap* hashmap_create(int size, struct hashmap_alloc alloc);
void hashmap_destroy(struct hashmap* hashmap);

struct hashmap_keyval* hashmap_set(struct hashmap* hashmap, char* key,
    value val);
struct value* hashmap_get(struct hashmap* hashmap, char* key);
