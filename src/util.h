#ifndef LIBFLOCK_UTIL_H_
#define LIBFLOCK_UTIL_H_

#include "libflock/flock.h"
#include <stdint.h>

uint64_t time_now(void);
struct flock_file *_flock_file_new(uint8_t *buf, size_t buf_len,
				   const char *path);

#endif
