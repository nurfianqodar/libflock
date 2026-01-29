#include "libflock/flock.h"
#include "libflock/version.h"
#include "util.h"
#include <openssl/evp.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h> 
#include <endian.h>

static const uint8_t FLOCK_MAGIC[FLOCK_MAGIC_LEN] = { 0xde, 0xad, 0xbe, 0xef };

static struct flock_file *_flock_file_new(uint8_t *buf, size_t buf_len,
					  const char *path);

static void _flock_write_header(uint8_t *buf, struct flock_key *key,
				size_t *off);

const uint8_t *flock_magic(void)
{
	return FLOCK_MAGIC;
}

struct flock_file *flock_encrypt(struct flock_file *file, struct flock_key *key)
{
	size_t off = 0;
	size_t out_len = file->buf_len + FLOCK_HEADER_LEN + FLOCK_TAG_LEN;
	uint8_t *out = mmap(NULL, out_len, PROT_WRITE | PROT_READ,
			    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (MAP_FAILED == out) {
		return NULL;
	}
	_flock_write_header(out, key, &off);

	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	if (!ctx) {
		munmap(out, out_len);
		return NULL;
	}
	if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)) {
		munmap(out, out_len);
		EVP_CIPHER_CTX_free(ctx);
		return NULL;
	}
	if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,
				     FLOCK_KEY_NONCE_LEN, NULL)) {
		munmap(out, out_len);
		EVP_CIPHER_CTX_free(ctx);
		return NULL;
	}
	if (1 !=
	    EVP_EncryptInit_ex(ctx, NULL, NULL, key->buf, key->param.nonce)) {
		munmap(out, out_len);
		EVP_CIPHER_CTX_free(ctx);
		return NULL;
	}
	int aad_len = 0; // dummy (for now)
	if (1 !=
	    EVP_EncryptUpdate(ctx, NULL, &aad_len, out, FLOCK_HEADER_LEN)) {
		munmap(out, out_len);
		EVP_CIPHER_CTX_free(ctx);
		return NULL;
	}
	int cip_len = 0;
	if (1 != EVP_EncryptUpdate(ctx, out + off, &cip_len, file->buf,
				   file->buf_len)) {
		munmap(out, out_len);
		EVP_CIPHER_CTX_free(ctx);
		return NULL;
	}
	off += cip_len;
	int tmp = 0;
	if (1 != EVP_EncryptFinal_ex(ctx, NULL, &tmp)) {
		munmap(out, out_len);
		EVP_CIPHER_CTX_free(ctx);
		return NULL;
	}
	if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, FLOCK_TAG_LEN,
				     out + off)) {
		munmap(out, out_len);
		EVP_CIPHER_CTX_free(ctx);
		return NULL;
	}
	off += FLOCK_TAG_LEN;
	if (off != out_len) {
		munmap(out, out_len);
		EVP_CIPHER_CTX_free(ctx);
		return NULL;
	}
	char *out_path = strdup(file->path);
	if (!out_path) {
		munmap(out, out_len);
		EVP_CIPHER_CTX_free(ctx);
		return NULL;
	}
	struct flock_file *f = _flock_file_new(out, out_len, out_path);
	if (!f) {
		munmap(out, out_len);
		EVP_CIPHER_CTX_free(ctx);
		free(out_path);
		return NULL;
	}
	EVP_CIPHER_CTX_free(ctx);
	return f;
}

struct flock_file *flock_decrypt(struct flock_file *file, struct flock_key *key)
{
	size_t meta_len = FLOCK_TAG_LEN + FLOCK_HEADER_LEN;
	if (file->buf_len < meta_len) {
        fprintf(stderr, "file has no meta\n");
		return NULL;
	}
	size_t out_len = file->buf_len - meta_len;
	uint8_t *out = mmap(NULL, out_len, PROT_WRITE | PROT_READ,
			    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (MAP_FAILED == out) {
        fprintf(stderr, "alloc error\n");
		return NULL;
	}
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	if (!ctx) {
        fprintf(stderr, "create ctx error\n");
		munmap(out, out_len);
		return NULL;
	}
	if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)) {
        fprintf(stderr, "dec init ctx error\n");
		munmap(out, out_len);
		EVP_CIPHER_CTX_free(ctx);
		return NULL;
	}
	if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,
				     FLOCK_KEY_NONCE_LEN, NULL)) {
        fprintf(stderr, "set iv len ctx error\n");
		munmap(out, out_len);
		EVP_CIPHER_CTX_free(ctx);
		return NULL;
	}
	if (1 !=
	    EVP_DecryptInit_ex(ctx, NULL, NULL, key->buf, key->param.nonce)) {
        fprintf(stderr, "reinit ctx error\n");
		munmap(out, out_len);
		EVP_CIPHER_CTX_free(ctx);
		return NULL;
	}
	int aad_len = 0; // dummy (for now)
	if (1 != EVP_DecryptUpdate(ctx, NULL, &aad_len, file->buf,
				   FLOCK_HEADER_LEN)) {
        fprintf(stderr, "update aad ctx error\n");
		munmap(out, out_len);
		EVP_CIPHER_CTX_free(ctx);
		return NULL;
	}
	int plain_len = 0;
	if (1 != EVP_DecryptUpdate(ctx, out, &plain_len,
				   file->buf + FLOCK_HEADER_LEN, out_len)) {
        fprintf(stderr, "decrypt cipher error\n");
		munmap(out, out_len);
		EVP_CIPHER_CTX_free(ctx);
		return NULL;
	}
	if ((size_t)plain_len != out_len) {
        fprintf(stderr, "plain != cipher error\n");
		munmap(out, out_len);
		EVP_CIPHER_CTX_free(ctx);
		return NULL;
	}
	if (1 !=
	    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, FLOCK_TAG_LEN,
				file->buf + file->buf_len - FLOCK_TAG_LEN)) {
        fprintf(stderr, "set tag error\n");
		munmap(out, out_len);
		EVP_CIPHER_CTX_free(ctx);
		return NULL;
	}
	int tmp = 0;
	if (1 != EVP_DecryptFinal_ex(ctx, NULL, &tmp)) {
        fprintf(stderr, "final error\n");
		munmap(out, out_len);
		EVP_CIPHER_CTX_free(ctx);
		return NULL;
	}
	char *out_path = strdup(file->path);
	if (!out_path) {
		munmap(out, out_len);
		EVP_CIPHER_CTX_free(ctx);
		return NULL;
	}
	struct flock_file *f = _flock_file_new(out, out_len, out_path);
	if (!f) {
		munmap(out, out_len);
		EVP_CIPHER_CTX_free(ctx);
		free(out_path);
		return NULL;
	}
	EVP_CIPHER_CTX_free(ctx);
	return f;
}

static struct flock_file *_flock_file_new(uint8_t *buf, size_t buf_len,
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

static void _flock_write_header(uint8_t *buf, struct flock_key *key,
				size_t *off)
{
	// file layout:
	// magic[4]version[3]timestamp[8]salt[FLOCK_KEY_SALT_LEN]nonce[FLOCK_KEY_NONCE_LEN]ciphertext[...rest]

	*off = 0;

	memcpy(buf + *off, flock_magic(), FLOCK_MAGIC_LEN);
	*off += FLOCK_MAGIC_LEN;

	memcpy(buf + *off, flock_version(), FLOCK_VERSION_LEN);
	*off += FLOCK_VERSION_LEN;

	uint64_t now = htole64(time_now());
	memcpy(buf + *off, &now, FLOCK_FILE_TIMESTAMP_LEN);
	*off += FLOCK_FILE_TIMESTAMP_LEN;

	memcpy(buf + *off, key->param.salt, FLOCK_KEY_SALT_LEN);
	*off += FLOCK_KEY_SALT_LEN;

	memcpy(buf + *off, key->param.nonce, FLOCK_KEY_NONCE_LEN);
	*off += FLOCK_KEY_NONCE_LEN;
}
