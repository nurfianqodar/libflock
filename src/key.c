#include "libflock/flock.h"
#include <argon2.h>
#include <openssl/rand.h>
#include <string.h>

int flock_key_load(struct flock_key *key, struct flock_key_param *param,
		   uint8_t *pwd, size_t pwd_len)
{
	memcpy(key->param.salt, param->salt, FLOCK_KEY_SALT_LEN);
	memcpy(key->param.nonce, param->nonce, FLOCK_KEY_NONCE_LEN);
	if (ARGON2_OK != argon2id_hash_raw(FLOCK_KEY_TIME_COST,
					   FLOCK_KEY_MEMORY_COST,
					   FLOCK_KEY_THREAD_COST, pwd, pwd_len,
					   key->param.salt, FLOCK_KEY_SALT_LEN,
					   key->buf, FLOCK_KEY_BUF_LEN)) {
		return -1;
	}
	return 0;
}

int flock_key_new(struct flock_key *key, uint8_t *pwd, size_t pwd_len)
{
	if (1 != RAND_bytes(key->param.nonce, FLOCK_KEY_NONCE_LEN)) {
		return -1;
	}
	if (1 != RAND_bytes(key->param.salt, FLOCK_KEY_SALT_LEN)) {
		return -1;
	}
	if (ARGON2_OK != argon2id_hash_raw(FLOCK_KEY_TIME_COST,
					   FLOCK_KEY_MEMORY_COST,
					   FLOCK_KEY_THREAD_COST, pwd, pwd_len,
					   key->param.salt, FLOCK_KEY_SALT_LEN,
					   key->buf, FLOCK_KEY_BUF_LEN)) {
		return -1;
	}
	return 0;
}

struct flock_key flock_key_zero(void)
{
	struct flock_key k;
	flock_key_reset(&k);
	return k;
}

void flock_key_reset(struct flock_key *key)
{
	memset(key->buf, 0, FLOCK_KEY_BUF_LEN);
	memset(key->param.nonce, 0, FLOCK_KEY_NONCE_LEN);
	memset(key->param.salt, 0, FLOCK_KEY_SALT_LEN);
}
