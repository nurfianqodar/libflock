#include "util.h"
#include <stdlib.h>
#include <time.h>

uint64_t time_now(void)
{
	return (uint64_t)time(NULL);
}

struct flock_file *_flock_file_new(uint8_t *buf, size_t buf_len,
				   const char *path)
{
	struct flock_file *f;
	f = malloc(sizeof *f);
	if (!f) {
		return NULL;
	}
	f->buf = buf;
	f->buf_len = buf_len;
	f->path = strdup(path);
	if (!f->path) {
		free(f);
		return NULL;
	}
	return f;
}
