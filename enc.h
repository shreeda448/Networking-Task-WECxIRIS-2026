#include "openssl/rand.h"
#include <stdint.h>
#define NONCE_SIZE 12
int gen_nonce(unsigned char *nonce);
int gen_enc_payload(uint8_t *payload_buf, uint8_t *enc_key,
                    unsigned char *nonce, uint8_t *msg);
