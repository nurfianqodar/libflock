#include "libflock/flock.h"
#include "libflock/version.h"
#include "util.h"
#include <fcntl.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <sys/stat.h>
#include <sys/mman.h>

static bool _flock_stat_is_valid(const struct stat *st);

static bool _flock_file_has_magic(uint8_t *buf);

struct flock_file *flock_file_load(const char *path)
{
	int fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		return NULL;
	}
	struct stat st;
	if (0 != fstat(fd, &st)) {
		close(fd);
		return NULL;
	}
	if (!_flock_stat_is_valid(&st)) {
		close(fd);
		return NULL;
	}
	size_t buf_len = (size_t)st.st_size;
	uint8_t *buf = mmap(NULL, buf_len, PROT_READ, MAP_PRIVATE, fd, 0);
	if (MAP_FAILED == buf) {
		close(fd);
		return NULL;
	}
	char *path_dup = strdup(path);
	if (!path_dup) {
		close(fd);
		munmap(buf, buf_len);
		return NULL;
	}

	struct flock_file *f = _flock_file_new(buf, buf_len, path_dup);
	if (!f) {
		close(fd);
		munmap(buf, buf_len);
		free(path_dup);
		return NULL;
	}
	close(fd);
	return f;
}

int flock_file_save(struct flock_file *file)
{
	int fd = open(file->path, O_RDWR | O_TRUNC | O_CREAT | O_CLOEXEC, 0664);
	if (fd < 0) {
		return -1;
	}
	if (0 != ftruncate(fd, file->buf_len)) {
		close(fd);
		return -1;
	}
	uint8_t *buf = mmap(NULL, file->buf_len, PROT_WRITE | PROT_READ,
			    MAP_SHARED, fd, 0);
	if (MAP_FAILED == buf) {
		close(fd);
		return -1;
	}
	memcpy(buf, file->buf, file->buf_len);
	msync(buf, file->buf_len, MS_SYNC);
	munmap(buf, file->buf_len);
	close(fd);
	return 0;
}

void flock_file_unload(struct flock_file *file)
{
	if (!file) {
		return;
	}
	munmap(file->buf, file->buf_len);
	free(file->path);
	free(file);
}

int flock_file_get_meta(struct flock_file *file, struct flock_meta *meta)
{
	if (file->buf_len < FLOCK_HEADER_LEN) {
		return -1;
	}
	if (!_flock_file_has_magic(file->buf)) {
		return -1;
	}
	// file layout:
	// magic[4]version[3]timestamp[8]salt[FLOCK_KEY_SALT_LEN]nonce[FLOCK_KEY_NONCE_LEN]ciphertext[...rest]
	size_t off = 0;
	off += FLOCK_MAGIC_LEN;
	memcpy(meta->version, file->buf + off, FLOCK_VERSION_LEN);
	off += FLOCK_VERSION_LEN;
	memcpy(&meta->timestamp, file->buf + off, FLOCK_FILE_TIMESTAMP_LEN);
	off += FLOCK_FILE_TIMESTAMP_LEN;
	memcpy(meta->param.salt, file->buf + off, FLOCK_KEY_SALT_LEN);
	off += FLOCK_KEY_SALT_LEN;
	memcpy(meta->param.nonce, file->buf + off, FLOCK_KEY_NONCE_LEN);
	off += FLOCK_KEY_NONCE_LEN;
	return 0;
}

int flock_file_set_path(struct flock_file *file, const char *path)
{
	char *new_path = strdup(path);
	if (!new_path) {
		return -1;
	}
	free(file->path);
	file->path = new_path;
	return 0;
}

static bool _flock_stat_is_valid(const struct stat *st)
{
	if (!S_ISREG(st->st_mode)) {
		return false;
	}
	if (st->st_size == 0) {
		return false;
	}
	return true;
}

static bool _flock_file_has_magic(uint8_t *buf)
{
	return memcmp(buf, flock_magic(), FLOCK_MAGIC_LEN) == 0;
}
