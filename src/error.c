#include "libflock/error.h"
#include <openssl/err.h>
#include <openssl/evp.h>

static _Thread_local int _flock_errno;

int *_flock_errno_loc(void)
{
	return &_flock_errno;
}

void _flock_errno_set_by_errno(int _errno)
{
	switch (_errno) {
	case ENOMEM:
		flock_errno = FLOCK_E_NOMEM;
		break;
	case EBUSY:
		flock_errno = FLOCK_E_BUSY;
		break;
	case ENOENT:
		flock_errno = FLOCK_E_NFOUND;
		break;
	case EINVAL:
		flock_errno = FLOCK_E_INVAL;
		break;
	default:
		flock_errno = FLOCK_E_UDEF;
	}
}

/* map OpenSSL AES-256-GCM errors to FLOCK error codes */
void _flock_errno_set_by_ossl(unsigned long e)
{
	if (e == 0) {
		flock_errno = FLOCK_OK;
		return;
	}

	unsigned int lib = ERR_GET_LIB(e);
	unsigned int reason = ERR_GET_REASON(e);

	switch (lib) {
	case ERR_LIB_EVP:
		switch (reason) {
		case EVP_R_BAD_DECRYPT:
		case EVP_R_DIFFERENT_PARAMETERS:
			flock_errno = FLOCK_E_INVKEY; // key/password salah
			break;
		case EVP_R_NO_KEY_SET:
			flock_errno = FLOCK_E_NODEC; // key belum diset
			break;
		case EVP_R_BAD_KEY_LENGTH:
		case EVP_R_UNSUPPORTED_KEYLENGTH:
			flock_errno = FLOCK_E_INVAL; // key length salah
			break;
		default:
			flock_errno = FLOCK_E_UDEF;
			break;
		}
		break;

	case ERR_LIB_SYS:
		flock_errno = FLOCK_E_NOMEM; // memory / OS-level error
		break;

	default:
		flock_errno = FLOCK_E_UDEF; // unknown
		break;
	}
}
