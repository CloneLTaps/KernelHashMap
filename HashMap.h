#pragma once

#ifndef HashMap_H
#define HashMap_H

#include <wdm.h>

struct hashmap_entry {
    void* key;
    void* data;
};

struct hashmap_base {
    size_t table_size_init;
    size_t table_size;
    size_t size;
    size_t key_size;
    size_t value_size;
    struct hashmap_entry* table;
    size_t(*hash)(const void*);
    int (*compare)(const void*, const void*);
    void* (*key_dup)(const void*, size_t);
    void (*key_free)(void*);
    void* (*value_dup)(const void*, size_t);
    void (*value_free)(void*);
};

void hashmap_base_init(struct hashmap_base* hb,
    size_t(*hash_func)(const void*), int (*compare_func)(const void*, const void*));
void hashmap_base_cleanup(struct hashmap_base* hb);

void hashmap_base_set_key_alloc_funcs(struct hashmap_base* hb, void* (*key_dup_func)(const void*, size_t), void (*key_free_func)(void*), size_t key_size);
void hashmap_base_set_value_alloc_funcs(struct hashmap_base* hb, void* (*value_dup_func)(const void*, size_t), void (*value_free_func)(void*), size_t value_size);

NTSTATUS hashmap_base_reserve(struct hashmap_base* hb, size_t capacity);

NTSTATUS hashmap_base_put(struct hashmap_base* hb, const void* key, void* data);
NTSTATUS hashmap_base_put_replace(struct hashmap_base* hb, const void* key, void* data);
void* hashmap_base_get(const struct hashmap_base* hb, const void* key);
BOOLEAN hashmap_contains(const struct hashmap_base* hb, const void* key);
void* hashmap_base_remove(struct hashmap_base* hb, const void* key);

void hashmap_base_clear(struct hashmap_base* hb);
void hashmap_base_reset(struct hashmap_base* hb);

struct hashmap_entry* hashmap_base_iter(const struct hashmap_base* hb, const struct hashmap_entry* pos);
BOOLEAN hashmap_base_iter_valid(const struct hashmap_base* hb, const struct hashmap_entry* iter);
BOOLEAN hashmap_base_iter_next(const struct hashmap_base* hb, struct hashmap_entry** iter);
BOOLEAN hashmap_base_iter_remove(struct hashmap_base* hb, struct hashmap_entry** iter);
const void* hashmap_base_iter_get_key(const struct hashmap_entry* iter);
void* hashmap_base_iter_get_data(const struct hashmap_entry* iter);
NTSTATUS hashmap_base_iter_set_data(struct hashmap_entry* iter, void* data);

double hashmap_base_load_factor(const struct hashmap_base* hb);
size_t hashmap_base_collisions(const struct hashmap_base* hb, const void* key);
double hashmap_base_collisions_mean(const struct hashmap_base* hb);
double hashmap_base_collisions_variance(const struct hashmap_base* hb);

size_t hashmap_hash_default(const void* data, size_t len);
size_t hashmap_hash_string(const char* key);
size_t hashmap_hash_string_i(const char* key);
int hashmap_int_compare_function(const void* a, const void* b);
size_t hashmap_int_hash_function(const void* key);
void* hashmap_generic_dup(const void* source, size_t size);
void hashmap_generic_free(void* memory);

#endif; // HashMap_H

