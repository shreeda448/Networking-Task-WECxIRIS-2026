#include "openssl/rand.h"
#include <stdint.h>
#define NONCE_SIZE 12
int gen_nonce(unsigned char *nonce);
int gcm_encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *aad,
                int aad_len, unsigned char *key, unsigned char *iv, int iv_len,
                unsigned char *ciphertext, unsigned char *tag, int *l);
