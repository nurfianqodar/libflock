
## Result File Layout
- 4 byte magic
- 3 byte
- 8 byte timestamp
- FLOCK_KEY_SALT_LEN byte salt (16 byte)
- FLOCK_KEY_NONCE_LEN byte nonce (12 byte)
- N byte ciphertext
- FLOCK_TAG_LEN byte tag (16 byte)
