#ifndef CONFIG_STORE_H
#define CONFIG_STORE_H

#include <stdbool.h>
#include <stddef.h>

typedef struct {
    char **items;
    size_t count;
    size_t capacity;
} string_list_t;

void string_list_init(string_list_t *list);
void string_list_free(string_list_t *list);
bool string_list_append(string_list_t *list, const char *value);
bool string_list_remove(string_list_t *list, const char *value);
bool string_list_contains(const string_list_t *list, const char *value);

bool config_load(string_list_t *paths, string_list_t *cdhashes);
bool config_save(const string_list_t *paths, const string_list_t *cdhashes);
bool config_add(string_list_t *list, const char *value);
bool config_remove(string_list_t *list, const char *value);
long long config_get_mtime_ns(const char *filename);

#endif
