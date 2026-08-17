#ifndef BYPASS_RUNTIME_H
#define BYPASS_RUNTIME_H

#include <stdbool.h>
#include <stddef.h>

bool bypass_run(const char * const *paths, size_t path_count,
                const char * const *cdhashes, size_t cdhash_count,
                bool verbose, bool allow_all, bool spoof_apple);

#endif
