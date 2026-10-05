#include "chat.h"
#include "enc.h"
#include "frame.h"
#include <stdint.h>

int gen_data_frame(uint8_t *msg, size_t msg_len, uint8_t *enc_key, Frame *f) {
  // 1. Generate a nonce
  unsigned char nonce[NONCE_SIZE];
  if (gen_nonce(nonce) != 0) {
    return -1;
  }
  // 2. Encrypt the message
  unsigned char ciphertext[msg_len];
  unsigned char tag[TAG_SIZE];
  int ciphertext_len = 0;
  if (gcm_encrypt(msg, msg_len, NULL, 0, enc_key, nonce, NONCE_SIZE, ciphertext,
                  tag, &ciphertext_len) != 0) {
    return -1;
  }
  if (ciphertext_len != (int)msg_len) {
    return -1;
  }
  // 3. Create frame
  f->type = MSG_DATA;
  f->len = NONCE_SIZE + ciphertext_len + TAG_SIZE;
  f->payload = malloc(f->len);
  if (f->payload == NULL) {
    return -1;
  }
  // 4. Construct payload
  memcpy(f->payload, nonce, NONCE_SIZE);
  memcpy(f->payload + NONCE_SIZE, ciphertext, ciphertext_len);
  memcpy(f->payload + NONCE_SIZE + ciphertext_len, tag, TAG_SIZE);
  return 0;
}
