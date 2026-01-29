#include "libflock/error.h"
#include "libflock/flock.h"
#include "libflock/version.h"
#include <errno.h>
#include <fcntl.h>
#include <openssl/evp.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

static bool _flock_stat_is_valid(const struct stat *st);

static bool _flock_file_has_magic(uint8_t *buf);

struct flock_file *flock_file_new(const char *path, uint8_t *buf,
				  size_t buf_len)
{
	struct flock_file *f;
	f = malloc(sizeof *f);
	if (!f) {
		_flock_errno_set_by_errno(errno);
		return NULL;
	}
	f->buf = buf;
	f->buf_len = buf_len;
	f->path = strdup(path);
	if (!f->path) {
		_flock_errno_set_by_errno(errno);
		free(f);
		return NULL;
	}
	return f;
}

struct flock_file *flock_file_load(const char *path)
{
	int fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		_flock_errno_set_by_errno(errno);
		return NULL;
	}
	struct stat st;
	if (0 != fstat(fd, &st)) {
		_flock_errno_set_by_errno(errno);
		close(fd);
		return NULL;
	}
	if (!_flock_stat_is_valid(&st)) { // set flock_errno on validation
		close(fd);
		return NULL;
	}
	size_t buf_len = (size_t)st.st_size;
	uint8_t *buf = mmap(NULL, buf_len, PROT_READ, MAP_PRIVATE, fd, 0);
	if (MAP_FAILED == buf) {
		_flock_errno_set_by_errno(errno);
		close(fd);
		return NULL;
	}
	char *path_dup = strdup(path);
	if (!path_dup) {
		_flock_errno_set_by_errno(errno);
		close(fd);
		munmap(buf, buf_len);
		return NULL;
	}
	struct flock_file *f = flock_file_new(path_dup, buf, buf_len);
	if (!f) {
		_flock_errno_set_by_errno(errno);
		close(fd);
		munmap(buf, buf_len);
		free(path_dup);
		return NULL;
	}
	flock_errno = FLOCK_OK;
	close(fd);
	return f;
}

int flock_file_save(struct flock_file *file)
{
	int fd = open(file->path, O_RDWR | O_TRUNC | O_CREAT | O_CLOEXEC, 0664);
	if (fd < 0) {
		_flock_errno_set_by_errno(errno);
		return -1;
	}
	if (0 != ftruncate(fd, file->buf_len)) {
		_flock_errno_set_by_errno(errno);
		close(fd);
		return -1;
	}
	uint8_t *buf = mmap(NULL, file->buf_len, PROT_WRITE | PROT_READ,
			    MAP_SHARED, fd, 0);
	if (MAP_FAILED == buf) {
		_flock_errno_set_by_errno(errno);
		close(fd);
		return -1;
	}
	memcpy(buf, file->buf, file->buf_len);
	if (0 != msync(buf, file->buf_len, MS_SYNC)) {
		_flock_errno_set_by_errno(errno);
		close(fd);
		munmap(buf, file->buf_len);
	}
	close(fd);
	munmap(buf, file->buf_len);
	return 0;
}

void flock_file_unload(struct flock_file *file)
{
	if (!file) {
		flock_errno = FLOCK_E_INVAL;
		return;
	}
	munmap(file->buf, file->buf_len);
	free(file->path);
	free(file);
}

int flock_file_get_meta(struct flock_file *file, struct flock_meta *meta)
{
	if (file->buf_len < (FLOCK_HEADER_LEN + FLOCK_TAG_LEN)) {
		flock_errno = FLOCK_E_NOENC;
		return -1;
	}
	if (!_flock_file_has_magic(file->buf)) {
		flock_errno = FLOCK_E_NOENC;
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
		_flock_errno_set_by_errno(errno);
		return -1;
	}
	free(file->path);
	file->path = new_path;
	return 0;
}

static bool _flock_stat_is_valid(const struct stat *st)
{
	if (!S_ISREG(st->st_mode)) {
		flock_errno = FLOCK_E_NFILE;
		return false;
	}
	if (st->st_size == 0) {
		flock_errno = FLOCK_E_EMPF;
		return false;
	}
	return true;
}

static bool _flock_file_has_magic(uint8_t *buf)
{
	return memcmp(buf, flock_magic(), FLOCK_MAGIC_LEN) == 0;
}
