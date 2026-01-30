#include "libflock/error.h"
#include "libflock/flock.h"
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void print_usage(char *arg1);

int main(int argc, char **argv)
{
	if (argc < 6) {
		printf("invalid args\n");
		print_usage(argv[0]);
		return EXIT_FAILURE;
	}
	const char *path_in = NULL;
	const char *path_out = NULL;
	const char *password = NULL;
	bool is_encrypt;

	if (argv[1][0] == 'd') {
		is_encrypt = false;
	} else if (argv[1][0] == 'e') {
		is_encrypt = true;
	} else {
		printf("invalid mode (use e/d)\n");
		print_usage(argv[0]);
		return EXIT_FAILURE;
	}
	for (int i = 2; i < argc; i++) {
		if (strcmp(argv[i], "-i") == 0 && i + 1 < argc) {
			path_in = argv[++i];
		} else if (strcmp(argv[i], "-o") == 0 && i + 1 < argc) {
			path_out = argv[++i];
		} else if (strcmp(argv[i], "-p") == 0 && i + 1 < argc) {
			password = argv[++i];
		} else {
			printf("invalid option\n");
			print_usage(argv[0]);
			return EXIT_FAILURE;
		}
	}
	if (path_in == NULL) {
		printf("input path must be set\n");
		print_usage(argv[0]);
		return EXIT_FAILURE;
	}
	if (password == NULL) {
		printf("password must be set\n");
		print_usage(argv[0]);
		return EXIT_FAILURE;
	}
	if (path_out == NULL) {
		printf("overwrite file %s\n", path_in);
		path_out = path_in;
	}

	struct flock_meta meta;
	struct flock_key key;

	struct flock_file *in, *out;

	in = flock_file_load(path_in);
	if (!in) {
		return EXIT_FAILURE;
	}

	if (is_encrypt) {
		if (flock_file_get_meta(in, &meta) == 0) {
			flock_file_unload(in);
			printf("error: file already encrypted");
			return EXIT_FAILURE;
		}
		if (flock_key_new(&key, (uint8_t *)password,
				  strlen(password)) != 0) {
			printf("error: unable to create key, code=%d\n",
			       flock_errno);
			flock_file_unload(in);
			return EXIT_FAILURE;
		}
		if (!(out = flock_encrypt(in, &key))) {
			printf("error: unable to encrypt, code=%d\n",
			       flock_errno);
			flock_file_unload(in);
			return EXIT_FAILURE;
		}
	} else {
		if (flock_file_get_meta(in, &meta) != 0) {
			printf("error: unable to get meta, code=%d\n",
			       flock_errno);
			flock_file_unload(in);
			return EXIT_FAILURE;
		}
		if (flock_key_load(&key, &meta.param, (uint8_t *)password,
				   strlen(password)) != 0) {
			printf("error: unable to load key, code=%d\n",
			       flock_errno);
			flock_file_unload(in);
			return EXIT_FAILURE;
		}
		if (!(out = flock_decrypt(in, &key))) {
			printf("error: unable to decrypt, code=%d\n",
			       flock_errno);
			flock_file_unload(in);
			return EXIT_FAILURE;
		}
	}

	if (flock_file_set_path(out, path_out) != 0) {
		printf("error: unable to set path, code=%d\n", flock_errno);
		flock_file_unload(in);
		flock_file_unload(out);
		return EXIT_FAILURE;
	}
	if (flock_file_save(out) != 0) {
		printf("error: unable to save, code=%d\n", flock_errno);
		flock_file_unload(in);
		flock_file_unload(out);
		return EXIT_FAILURE;
	}
	flock_file_unload(in);
	flock_file_unload(out);

	return 0;
}

void print_usage(char *arg0)
{
	printf("Usage:\n%s e|d -i <input> -o <output> -p <password>\n", arg0);
}
