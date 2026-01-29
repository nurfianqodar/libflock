#include <libflock/version.h>
#include <stdbool.h>
#include <string.h>

static const uint8_t FLOCK_VERSION[FLOCK_VERSION_LEN] = { FLOCK_VERSION_MAJOR,
							  FLOCK_VERSION_MINOR,
							  FLOCK_VERSION_PATCH };

const uint8_t *flock_version(void)
{
	return FLOCK_VERSION;
}

bool flock_version_is_match(uint8_t a[3], uint8_t b[3])
{
	return memcmp(a, b, FLOCK_VERSION_LEN) == 0;
}
