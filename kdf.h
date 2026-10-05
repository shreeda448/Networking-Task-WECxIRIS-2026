#ifndef CSL_KDF_H
#define CSL_KDF_H
#include <stddef.h>
#include <stdint.h>

#define KDF_LEN 32 // SHA-256 output size in bytes

int hmac_sha256(const uint8_t *key, size_t key_len, const uint8_t *data,
                size_t data_len, uint8_t out[KDF_LEN]);
// Extract: prk = HMAC(salt, secret). Returns 0 on success, -1 on failure.
int kdf_extract(const uint8_t *salt, size_t salt_len, const uint8_t *secret,
                size_t secret_len, uint8_t prk[KDF_LEN]);

// Expand: out = HMAC(prk, label). One 32-byte key per label.
// Returns 0 on success, -1 on failure.
int kdf_expand(const uint8_t prk[KDF_LEN], const char *label,
               uint8_t out[KDF_LEN]);

#endif
