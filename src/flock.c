#include "libflock/flock.h"
#include "libflock/error.h"
#include "libflock/version.h"
#include "util.h"
#include <endian.h>
#include <errno.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

// ============================
// Static Values
// ============================
static const uint8_t FLOCK_MAGIC[FLOCK_MAGIC_LEN] = { 0xde, 0xad, 0xbe, 0xef };

// ============================
// Static Headers
// ============================

/**
 * @brief write header to buffer and change the offset
 * 
 * Offset must be started from 0 because header is
 * placed at the beginning of the file
 */
static void _flock_write_header(uint8_t *buf, struct flock_key *key,
				size_t *off);

// flock_magic implementation
const uint8_t *flock_magic(void)
{
	return FLOCK_MAGIC;
}

// flock_encrypt implementation
// flow:
// - Create ctx
// - Init Gcm
// - Set iv or nonce len
// - Reinit by key and nonce value
// - Create buffer for output
// - Write header to buffer
// - Add header to context
// - Encrypt plaintext
// - Finalize
// - Get and write tag to the end of the file
struct flock_file *flock_encrypt(struct flock_file *file, struct flock_key *key)
{
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	if (!ctx) {
		_flock_errno_set_by_ossl(ERR_get_error());
		return NULL;
	}
	if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)) {
		_flock_errno_set_by_ossl(ERR_get_error());
		EVP_CIPHER_CTX_free(ctx);
		return NULL;
	}
	if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,
				     FLOCK_KEY_NONCE_LEN, NULL)) {
		_flock_errno_set_by_ossl(ERR_get_error());
		EVP_CIPHER_CTX_free(ctx);
		return NULL;
	}
	if (1 !=
	    EVP_EncryptInit_ex(ctx, NULL, NULL, key->buf, key->param.nonce)) {
		_flock_errno_set_by_ossl(ERR_get_error());
		EVP_CIPHER_CTX_free(ctx);
		return NULL;
	}
	size_t off = 0; // write offset
	size_t out_len = file->buf_len + FLOCK_HEADER_LEN + FLOCK_TAG_LEN;
	uint8_t *out = mmap(NULL, out_len, PROT_WRITE | PROT_READ,
			    MAP_PRIVATE | MAP_ANONYMOUS, -1,
			    0); // Create cipher file buffer
	if (MAP_FAILED == out) {
		_flock_errno_set_by_errno(errno);
		EVP_CIPHER_CTX_free(ctx);
		return NULL;
	}
	_flock_write_header(out, key, &off); // write header first
	int aad_len = 0; // dummy (for now)
	if (1 !=
	    EVP_EncryptUpdate(ctx, NULL, &aad_len, out, FLOCK_HEADER_LEN)) {
		_flock_errno_set_by_ossl(ERR_get_error());
		EVP_CIPHER_CTX_free(ctx);
		munmap(out, out_len);
		return NULL;
	}
	int cip_len = 0;
	if (1 != EVP_EncryptUpdate(ctx, out + off, &cip_len, file->buf,
				   file->buf_len)) {
		_flock_errno_set_by_ossl(ERR_get_error());
		munmap(out, out_len);
		EVP_CIPHER_CTX_free(ctx);
		return NULL;
	}
	off += cip_len;
	int tmp = 0;
	if (1 != EVP_EncryptFinal_ex(ctx, NULL, &tmp)) {
		_flock_errno_set_by_ossl(ERR_get_error());
		munmap(out, out_len);
		EVP_CIPHER_CTX_free(ctx);
		return NULL;
	}
	if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, FLOCK_TAG_LEN,
				     out + off)) {
		_flock_errno_set_by_ossl(ERR_get_error());
		munmap(out, out_len);
		EVP_CIPHER_CTX_free(ctx);
		return NULL;
	}
	off += FLOCK_TAG_LEN;
	if (off != out_len) {
		flock_errno = FLOCK_E_UDEF;
		munmap(out, out_len);
		EVP_CIPHER_CTX_free(ctx);
		return NULL;
	}
	char *out_path = strdup(file->path);
	if (!out_path) {
		_flock_errno_set_by_errno(errno);
		munmap(out, out_len);
		EVP_CIPHER_CTX_free(ctx);
		return NULL;
	}
	struct flock_file *f = flock_file_new(out_path, out, out_len);
	if (!f) {
		munmap(out, out_len);
		EVP_CIPHER_CTX_free(ctx);
		free(out_path);
		return NULL;
	}
	EVP_CIPHER_CTX_free(ctx);
	return f;
}

// flock_decrypt implementation
// flow:
// - Create ctx
// - Init decrypt GCM
// - Set iv or nonce len
// - Reinit with key and nonce value
// - Add header to ctx
// - Create plaintext buffer
// - Decrypt ciphertext
// - Set tag
// - Finalize
struct flock_file *flock_decrypt(struct flock_file *file, struct flock_key *key)
{
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	if (!ctx) {
		return NULL;
	}
	if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)) {
		EVP_CIPHER_CTX_free(ctx);
		return NULL;
	}
	if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,
				     FLOCK_KEY_NONCE_LEN, NULL)) {
		EVP_CIPHER_CTX_free(ctx);
		return NULL;
	}
	if (1 !=
	    EVP_DecryptInit_ex(ctx, NULL, NULL, key->buf, key->param.nonce)) {
		EVP_CIPHER_CTX_free(ctx);
		return NULL;
	}
	int aad_len = 0; // dummy (for now)
	if (1 != EVP_DecryptUpdate(ctx, NULL, &aad_len, file->buf,
				   FLOCK_HEADER_LEN)) {
		EVP_CIPHER_CTX_free(ctx);
		return NULL;
	}
	size_t meta_len = FLOCK_TAG_LEN + FLOCK_HEADER_LEN;
	size_t out_len = file->buf_len - meta_len;
	uint8_t *out = mmap(NULL, out_len, PROT_WRITE | PROT_READ,
			    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (MAP_FAILED == out) {
		EVP_CIPHER_CTX_free(ctx);
		return NULL;
	}
	int plain_len = 0;
	if (1 != EVP_DecryptUpdate(ctx, out, &plain_len,
				   file->buf + FLOCK_HEADER_LEN, out_len)) {
		munmap(out, out_len);
		EVP_CIPHER_CTX_free(ctx);
		return NULL;
	}
	if ((size_t)plain_len != out_len) {
		munmap(out, out_len);
		EVP_CIPHER_CTX_free(ctx);
		return NULL;
	}
	if (1 !=
	    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, FLOCK_TAG_LEN,
				file->buf + file->buf_len - FLOCK_TAG_LEN)) {
		munmap(out, out_len);
		EVP_CIPHER_CTX_free(ctx);
		return NULL;
	}
	int tmp = 0;
	if (1 != EVP_DecryptFinal_ex(ctx, NULL, &tmp)) {
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
	struct flock_file *f = flock_file_new(out_path, out, out_len);
	if (!f) {
		munmap(out, out_len);
		EVP_CIPHER_CTX_free(ctx);
		free(out_path);
		return NULL;
	}
	EVP_CIPHER_CTX_free(ctx);
	return f;
}

/**
 * @brief Write file header to buffer
 *
 * File header layout is
 * 4 byte magic
 * 3 byte version
 * 8 byte timestamp
 * 16 byte salt
 * 16 byte nonce
 *
 *
 * and then ciphertext
 * and then 16 byte tag
 *
 */
static void _flock_write_header(uint8_t *buf, struct flock_key *key,
				size_t *off)
{
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
