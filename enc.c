#include "enc.h"
int gen_nonce(unsigned char *nonce) {
  if (RAND_bytes(nonce, NONCE_SIZE) != 1) {
    return -1;
  }
  return 0;
}
int gen_enc_payload(uint8_t *payload_buf, uint8_t *enc_key,
                    unsigned char *nonce, uint8_t *msg) {

  return 0;
}
