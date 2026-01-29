#ifndef LIBFLOCK_ERROR_H_
#define LIBFLOCK_ERROR_H_

int *_flock_errno_loc(void);
void _flock_errno_set_by_errno(int _errno);
void _flock_errno_set_by_ossl(unsigned long e);

#define flock_errno (*_flock_errno_loc())

#define FLOCK_OK 0
#define FLOCK_E_UDEF -1
#define FLOCK_E_NOMEM -2
#define FLOCK_E_BUSY -3
#define FLOCK_E_INVAL -4 /* invalid arguments */
#define FLOCK_E_EMPF -5 /* empty file */
#define FLOCK_E_NOENC -6 /* try to encrypt encrypted */
#define FLOCK_E_NODEC -7 /* try to decrypt encrypted */
#define FLOCK_E_INVKEY -8 /* invalid key */
#define FLOCK_E_NFILE -9 /* invalid file */
#define FLOCK_E_NFOUND -10 /* not found */

#endif
