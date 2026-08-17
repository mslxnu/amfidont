#ifndef DAEMON_RUNTIME_H
#define DAEMON_RUNTIME_H

#include <stdbool.h>
#include <stddef.h>

bool daemon_start(const char * const *paths, size_t path_count,
                  const char * const *cdhashes, size_t cdhash_count,
                  bool verbose, bool allow_all, bool spoof_apple);

#endif
