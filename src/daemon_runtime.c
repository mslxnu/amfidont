#include "daemon_runtime.h"

#include "bypass_runtime.h"

#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

bool daemon_start(const char * const *paths, size_t path_count,
                  const char * const *cdhashes, size_t cdhash_count,
                  bool verbose, bool allow_all, bool spoof_apple) {
    pid_t pid = fork();
    if (pid < 0) {
        fprintf(stderr, "Failed to fork: %s\n", strerror(errno));
        return false;
    }

    if (pid > 0) {
        if (verbose) {
            printf("Starting daemon with pid %d\n", pid);
        } else {
            printf("amfidont daemon started (pid: %d)\n", pid);
        }
        return true;
    }

    if (setsid() < 0) {
        fprintf(stderr, "Failed to create new session: %s\n", strerror(errno));
        exit(1);
    }

    signal(SIGCHLD, SIG_IGN);
    signal(SIGHUP, SIG_IGN);

    for (int fd = 0; fd < 64; fd++) {
        close(fd);
    }

    umask(0);

    bypass_run(paths, path_count, cdhashes, cdhash_count, verbose, allow_all, spoof_apple);
    exit(0);
}
