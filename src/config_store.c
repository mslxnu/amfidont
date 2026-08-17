#include "config_store.h"

#include "amfidont.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

bool string_list_append(string_list_t *list, const char *value) {
    if (list->count >= list->capacity) {
        size_t new_cap = list->capacity ? list->capacity * 2 : 8;
        char **new_items = (char **)realloc(list->items, new_cap * sizeof(char *));
        if (!new_items) return false;
        list->items = new_items;
        list->capacity = new_cap;
    }
    list->items[list->count++] = strdup(value);
    return true;
}

bool string_list_remove(string_list_t *list, const char *value) {
    for (size_t i = 0; i < list->count; i++) {
        if (strcmp(list->items[i], value) == 0) {
            free(list->items[i]);
            for (size_t j = i + 1; j < list->count; j++) {
                list->items[j - 1] = list->items[j];
            }
            list->count--;
            return true;
        }
    }
    return false;
}

bool string_list_contains(const string_list_t *list, const char *value) {
    for (size_t i = 0; i < list->count; i++) {
        if (strcmp(list->items[i], value) == 0) {
            return true;
        }
    }
    return false;
}

void string_list_init(string_list_t *list) {
    memset(list, 0, sizeof(*list));
}

void string_list_free(string_list_t *list) {
    for (size_t i = 0; i < list->count; i++) {
        free(list->items[i]);
    }
    free(list->items);
    memset(list, 0, sizeof(*list));
}

static bool read_list_file(const char *path, string_list_t *list) {
    FILE *fp = fopen(path, "r");
    if (!fp) return true;

    char line[4096];
    while (fgets(line, sizeof(line), fp)) {
        size_t len = strlen(line);
        while (len && (line[len - 1] == '\n' || line[len - 1] == '\r')) {
            line[--len] = '\0';
        }
        if (len > 0) {
            string_list_append(list, line);
        }
    }
    fclose(fp);
    return true;
}

static bool write_list_file(const char *path, const string_list_t *list) {
    FILE *fp = fopen(path, "w");
    if (!fp) {
        char dir_path[4096];
        strncpy(dir_path, path, sizeof(dir_path) - 1);
        dir_path[sizeof(dir_path) - 1] = '\0';
        char *last_slash = strrchr(dir_path, '/');
        if (last_slash) {
            *last_slash = '\0';
            mkdir(dir_path, 0755);
        }
        fp = fopen(path, "w");
        if (!fp) return false;
    }

    for (size_t i = 0; i < list->count; i++) {
        fputs(list->items[i], fp);
        fputc('\n', fp);
    }
    fclose(fp);
    return true;
}

bool config_load(string_list_t *paths, string_list_t *cdhashes) {
    char paths_file[4096];
    char cdhashes_file[4096];

    const char *home = getenv("HOME");
    if (!home) home = "";

    snprintf(paths_file, sizeof(paths_file), "%s/%s/%s", home, AMFIDONT_CONFIG_DIR, AMFIDONT_PATHS_FILE);
    snprintf(cdhashes_file, sizeof(cdhashes_file), "%s/%s/%s", home, AMFIDONT_CONFIG_DIR, AMFIDONT_CDHASHES_FILE);

    read_list_file(paths_file, paths);
    read_list_file(cdhashes_file, cdhashes);
    return true;
}

bool config_save(const string_list_t *paths, const string_list_t *cdhashes) {
    char paths_file[4096];
    char cdhashes_file[4096];

    const char *home = getenv("HOME");
    if (!home) home = "";

    snprintf(paths_file, sizeof(paths_file), "%s/%s/%s", home, AMFIDONT_CONFIG_DIR, AMFIDONT_PATHS_FILE);
    snprintf(cdhashes_file, sizeof(cdhashes_file), "%s/%s/%s", home, AMFIDONT_CONFIG_DIR, AMFIDONT_CDHASHES_FILE);

    return write_list_file(paths_file, paths) && write_list_file(cdhashes_file, cdhashes);
}

bool config_add(string_list_t *list, const char *value) {
    if (string_list_contains(list, value)) {
        return false;
    }
    return string_list_append(list, value);
}

bool config_remove(string_list_t *list, const char *value) {
    return string_list_remove(list, value);
}

long long config_get_mtime_ns(const char *filename) {
    const char *home = getenv("HOME");
    if (!home) home = "";

    char path[4096];
    snprintf(path, sizeof(path), "%s/%s/%s", home, AMFIDONT_CONFIG_DIR, filename);

    struct stat st;
    if (stat(path, &st) != 0) {
        return -1;
    }
    return (long long)st.st_mtimespec.tv_sec * 1000000000LL + (long long)st.st_mtimespec.tv_nsec;
}
