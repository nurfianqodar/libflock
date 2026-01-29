#ifndef LIBFLOCK_VERSION_H_
#define LIBFLOCK_VERSION_H_

#include <stdbool.h>
#include <stdint.h>
#define FLOCK_VERSION_STRING "0.0.0"

#define FLOCK_VERSION_MAJOR 0
#define FLOCK_VERSION_MINOR 0
#define FLOCK_VERSION_PATCH 0
#define FLOCK_VERSION_LEN 3

bool flock_version_is_match(uint8_t[3], uint8_t[3]);
const uint8_t *flock_version(void);

#endif // !LIBFLOCK_VERSION_H_
