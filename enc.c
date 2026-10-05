#include "enc.h"
int gen_nonce(unsigned char *nonce) {
  if (RAND_bytes(nonce, NONCE_SIZE) != 1) {
    return -1;
  }
  return 0;
}

int gcm_encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *aad,
                int aad_len, unsigned char *key, unsigned char *iv, int iv_len,
                unsigned char *ciphertext, unsigned char *tag, int *l) {
  EVP_CIPHER_CTX *ctx;
  int len;
  int ciphertext_len;

  /* Create and initialise the context */
  if (!(ctx = EVP_CIPHER_CTX_new()))
    return -1;

  /* Initialise the encryption operation */
  if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
    goto error;

  /* Set IV length */
  if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL))
    goto error;

  /* Initialise key and IV */
  if (1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv))
    goto error;

  /* Provide AAD */
  if (1 != EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len))
    goto error;

  /* Encrypt plaintext */
  if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
    goto error;

  ciphertext_len = len;

  /* Finalise encryption */
  if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
    goto error;

  ciphertext_len += len;

  /* Get authentication tag */
  if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag))
    goto error;

  /* Clean up */
  EVP_CIPHER_CTX_free(ctx);

  *l = ciphertext_len;
  return 0;

error:
  EVP_CIPHER_CTX_free(ctx);
  return -1;
}

int gcm_decrypt(unsigned char *ciphertext, int ciphertext_len,
                unsigned char *aad, int aad_len, unsigned char *tag,
                unsigned char *key, unsigned char *iv, int iv_len,
                unsigned char *plaintext) {
  EVP_CIPHER_CTX *ctx;
  int len;
  int plaintext_len;
  int ret;

  /* Create and initialise the context */
  if (!(ctx = EVP_CIPHER_CTX_new()))
    return -1;

  /* Initialise the decryption operation */
  if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
    goto error;

  /* Set IV length */
  if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL))
    goto error;

  /* Initialise key and IV */
  if (1 != EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv))
    goto error;

  /* Provide AAD */
  if (1 != EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len))
    goto error;

  /* Decrypt ciphertext */
  if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
    goto error;

  plaintext_len = len;

  /* Set expected authentication tag */
  if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag))
    goto error;

  /*
   * Finalise decryption.
   *
   * ret == 1 -> authentication succeeded
   * ret == 0 -> authentication failed
   */
  ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);

  EVP_CIPHER_CTX_free(ctx);

  if (ret > 0) {
    plaintext_len += len;
    return plaintext_len;
  }

  /* Authentication/tag verification failed */
  return -1;

error:
  EVP_CIPHER_CTX_free(ctx);
  return -1;
}
