#ifndef LIBFLOCK_H_
#define LIBFLOCK_H_

#include <stddef.h>
#include <stdint.h>

#define FLOCK_KEY_BUF_LEN 32 // aes 256 gcm key

#define FLOCK_KEY_SALT_LEN 16 // argon2 salt

#define FLOCK_KEY_NONCE_LEN 12 // aes 256 gcm nonce / iv

#define FLOCK_KEY_TIME_COST 4 // argon2 time cost

#define FLOCK_KEY_MEMORY_COST (1024 * 128) // argon2 mem cost 128 MB

#define FLOCK_KEY_THREAD_COST 4 // argon2 paralellism

#define FLOCK_TAG_LEN 16 // aes tag len

#define FLOCK_MAGIC_LEN 4

#define FLOCK_FILE_TIMESTAMP_LEN 8

// file layout:
// magic[4]version[3]timestamp[8]salt[FLOCK_KEY_SALT_LEN]nonce[FLOCK_KEY_NONCE_LEN]ciphertext[...rest]
#define FLOCK_HEADER_LEN                                                  \
	(FLOCK_MAGIC_LEN + FLOCK_VERSION_LEN + FLOCK_FILE_TIMESTAMP_LEN + \
	 FLOCK_KEY_SALT_LEN + FLOCK_KEY_NONCE_LEN)

#define FLOKC_CIPFILE_MIN_LEN (FLOCK_HEADER_LEN + FLOCK_TAG_LEN)

struct flock_key_param {
	uint8_t nonce[FLOCK_KEY_NONCE_LEN];
	uint8_t salt[FLOCK_KEY_SALT_LEN];
};

struct flock_key {
	struct flock_key_param param;
	uint8_t buf[256];
};

const uint8_t *flock_magic(void);

/**
 * @brief Create new `flock_key` from password
 *
 * @param key destination buffer pointer
 * @param pwd password
 * @param pwd_len password length
 *
 * @return 0 if success else -1
 */
int flock_key_new(struct flock_key *key, uint8_t *pwd, size_t pwd_len);

/**
 * @brief Create key from provided param
 *
 * Used when decrypt some file because the file only store the param
 *
 * @param key destination buffer pointer
 * @param param loaded `flock_key_param` for generate the key
 * @param pwd password
 * @param pwd_len password length
 */
int flock_key_load(struct flock_key *key, struct flock_key_param *param,
		   uint8_t *pwd, size_t pwd_len);

/**
 * @brief Create key and fill buffers with zero as well
 *
 * @return zeroed buffers `flock_key` structure
 */
struct flock_key flock_key_zero(void); // idk did we realy need this

void flock_key_reset(struct flock_key *key);

struct flock_meta {
	uint8_t version[3];
	uint64_t timestamp;
	struct flock_key_param param;
};

struct flock_file {
	uint8_t *buf;
	char *path;
	size_t buf_len;
};

struct flock_file *flock_file_load(const char *path);

struct flock_file *flock_file_new(const char *path, uint8_t *buf,
				  size_t buf_len);

void flock_file_unload(struct flock_file *file);

int flock_file_save(struct flock_file *file);

int flock_file_get_meta(struct flock_file *file, struct flock_meta *meta);

int flock_file_set_path(struct flock_file *file, const char *path);

struct flock_file *flock_encrypt(struct flock_file *file,
				 struct flock_key *key);

struct flock_file *flock_decrypt(struct flock_file *file,
				 struct flock_key *key);

#endif // !LIBFLOCK_H_
