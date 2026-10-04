#include "kdf.h"
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <string.h>

// HMAC-SHA256(key, data) -> out. Both phases are just this call with different
// arguments.
static int hmac_sha256(const uint8_t *key, size_t key_len, const uint8_t *data,
                       size_t data_len, uint8_t out[KDF_LEN]) {
  unsigned int out_len = 0;
  if (!HMAC(EVP_sha256(), key, (int)key_len, data, data_len, out, &out_len) ||
      out_len != KDF_LEN)
    return -1;
  return 0;
}

// the SALT is the HMAC key and the secret is the data
int kdf_extract(const uint8_t *salt, size_t salt_len, const uint8_t *secret,
                size_t secret_len, uint8_t prk[KDF_LEN]) {
  if (!salt || salt_len == 0 || !secret)
    return -1;
  return hmac_sha256(salt, salt_len, secret, secret_len, prk);
}

// the PRK is the HMAC key and the label is the data
int kdf_expand(const uint8_t prk[KDF_LEN], const char *label,
               uint8_t out[KDF_LEN]) {
  if (!label)
    return -1;
  return hmac_sha256(prk, KDF_LEN, (const uint8_t *)label, strlen(label), out);
}
