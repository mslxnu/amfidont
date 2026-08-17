#include "amfidont.h"

#include "bypass_runtime.h"
#include "config_store.h"
#include "daemon_runtime.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <stdbool.h>
#include <stddef.h>

static void print_usage(const char *progname) {
    fprintf(stdout,
        "Usage: %s [OPTIONS] COMMAND [ARGS]...\n"
        "\n"
        "A simple utility for bypassing amfid signature verification\n"
        "\n"
        "Options:\n"
        "  --path, -p TEXT      path of executable to allow (can be specified multiple times)\n"
        "  --cdhash, -c TEXT    cdhash of executable to allow (can be specified multiple times)\n"
        "  --verbose, -v        enable verbose output\n"
        "  --allow-all          allow all validations to pass\n"
        "  --spoof-apple, -S    patch isApple to return true for allowed binaries\n"
        "  --help               show this help message\n"
        "\n"
        "Commands:\n"
        "  daemon        Start amfidont in daemon mode.\n"
        "  add-path      Add an allowed path prefix to persistent configuration.\n"
        "  remove-path   Remove an allowed path prefix from persistent configuration.\n"
        "  add-cdhash    Add an allowed cdhash to persistent configuration.\n"
        "  remove-cdhash Remove an allowed cdhash from persistent configuration.\n",
        progname);
}

static int cmd_daemon(int argc, char **argv) {
    const char *paths[256];
    size_t path_count = 0;
    const char *cdhashes[256];
    size_t cdhash_count = 0;
    bool verbose = false;
    bool allow_all = false;
    bool spoof_apple = false;

    int opt;
    int longidx;
    static struct option long_opts[] = {
        {"path",        required_argument, 0, 'p'},
        {"cdhash",      required_argument, 0, 'c'},
        {"verbose",     no_argument,       0, 'v'},
        {"allow-all",   no_argument,       0, 'a'},
        {"spoof-apple", no_argument,       0, 'S'},
        {"help",        no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };

    while ((opt = getopt_long(argc, argv, "p:c:vSah", long_opts, &longidx)) != -1) {
        switch (opt) {
            case 'p':
                if (path_count < 256) paths[path_count++] = optarg;
                break;
            case 'c':
                if (cdhash_count < 256) cdhashes[cdhash_count++] = optarg;
                break;
            case 'v':
                verbose = true;
                break;
            case 'a':
                allow_all = true;
                break;
            case 'S':
                spoof_apple = true;
                break;
            case 'h':
                print_usage(argv[0]);
                return 0;
            default:
                print_usage(argv[0]);
                return 1;
        }
    }

    return daemon_start(paths, path_count, cdhashes, cdhash_count,
                        verbose, allow_all, spoof_apple) ? 0 : 1;
}

static int cmd_add_path(const char *path) {
    string_list_t paths, cdhashes;
    string_list_init(&paths);
    string_list_init(&cdhashes);
    config_load(&paths, &cdhashes);

    bool added = config_add(&paths, path);
    config_save(&paths, &cdhashes);

    string_list_free(&paths);
    string_list_free(&cdhashes);

    if (added) {
        printf("added path: %s\n", path);
    } else {
        printf("path already present: %s\n", path);
    }
    return 0;
}

static int cmd_remove_path(const char *path) {
    string_list_t paths, cdhashes;
    string_list_init(&paths);
    string_list_init(&cdhashes);
    config_load(&paths, &cdhashes);

    bool removed = config_remove(&paths, path);
    config_save(&paths, &cdhashes);

    string_list_free(&paths);
    string_list_free(&cdhashes);

    if (removed) {
        printf("removed path: %s\n", path);
    } else {
        printf("path not found: %s\n", path);
    }
    return 0;
}

static int cmd_add_cdhash(const char *cdhash) {
    string_list_t paths, cdhashes;
    string_list_init(&paths);
    string_list_init(&cdhashes);
    config_load(&paths, &cdhashes);

    bool added = config_add(&cdhashes, cdhash);
    config_save(&paths, &cdhashes);

    string_list_free(&paths);
    string_list_free(&cdhashes);

    if (added) {
        printf("added cdhash: %s\n", cdhash);
    } else {
        printf("cdhash already present: %s\n", cdhash);
    }
    return 0;
}

static int cmd_remove_cdhash(const char *cdhash) {
    string_list_t paths, cdhashes;
    string_list_init(&paths);
    string_list_init(&cdhashes);
    config_load(&paths, &cdhashes);

    bool removed = config_remove(&cdhashes, cdhash);
    config_save(&paths, &cdhashes);

    string_list_free(&paths);
    string_list_free(&cdhashes);

    if (removed) {
        printf("removed cdhash: %s\n", cdhash);
    } else {
        printf("cdhash not found: %s\n", cdhash);
    }
    return 0;
}

int main(int argc, char **argv) {
    const char *paths[256];
    size_t path_count = 0;
    const char *cdhashes[256];
    size_t cdhash_count = 0;
    bool verbose = false;
    bool allow_all = false;
    bool spoof_apple = false;

    int opt;
    int longidx;
    static struct option long_opts[] = {
        {"path",        required_argument, 0, 'p'},
        {"cdhash",      required_argument, 0, 'c'},
        {"verbose",     no_argument,       0, 'v'},
        {"allow-all",   no_argument,       0, 'a'},
        {"spoof-apple", no_argument,       0, 'S'},
        {"help",        no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };

    while ((opt = getopt_long(argc, argv, "p:c:vSah", long_opts, &longidx)) != -1) {
        switch (opt) {
            case 'p':
                if (path_count < 256) paths[path_count++] = optarg;
                break;
            case 'c':
                if (cdhash_count < 256) cdhashes[cdhash_count++] = optarg;
                break;
            case 'v':
                verbose = true;
                break;
            case 'a':
                allow_all = true;
                break;
            case 'S':
                spoof_apple = true;
                break;
            case 'h':
                print_usage(argv[0]);
                return 0;
            default:
                print_usage(argv[0]);
                return 1;
        }
    }

    if (optind < argc) {
        const char *cmd = argv[optind];

        if (strcmp(cmd, "daemon") == 0) {
            return cmd_daemon(argc - optind, argv + optind);
        } else if (strcmp(cmd, "add-path") == 0) {
            if (optind + 1 >= argc) {
                fprintf(stderr, "add-path requires a path argument\n");
                return 1;
            }
            return cmd_add_path(argv[optind + 1]);
        } else if (strcmp(cmd, "remove-path") == 0) {
            if (optind + 1 >= argc) {
                fprintf(stderr, "remove-path requires a path argument\n");
                return 1;
            }
            return cmd_remove_path(argv[optind + 1]);
        } else if (strcmp(cmd, "add-cdhash") == 0) {
            if (optind + 1 >= argc) {
                fprintf(stderr, "add-cdhash requires a cdhash argument\n");
                return 1;
            }
            return cmd_add_cdhash(argv[optind + 1]);
        } else if (strcmp(cmd, "remove-cdhash") == 0) {
            if (optind + 1 >= argc) {
                fprintf(stderr, "remove-cdhash requires a cdhash argument\n");
                return 1;
            }
            return cmd_remove_cdhash(argv[optind + 1]);
        } else {
            fprintf(stderr, "Unknown command: %s\n", cmd);
            print_usage(argv[0]);
            return 1;
        }
    }

    return bypass_run(paths, path_count, cdhashes, cdhash_count,
                      verbose, allow_all, spoof_apple) ? 0 : 1;
}
