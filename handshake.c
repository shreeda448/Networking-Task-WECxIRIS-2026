#include "handshake.h"
#include "dh.h"
#include "frame.h"
#include "kdf.h"
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <stdint.h>
#include <string.h>

Keys *gen_key_pair() {
  Keys *k = NULL;
  BIGNUM *priv = dh_generate_private();
  if (!priv) {
    return NULL;
  }
  BIGNUM *pub = dh_generate_public(priv);
  if (!valid_pub_key(pub)) {
    BN_free(pub);
    BN_clear_free(priv);
    priv = NULL;
    pub = NULL;
    return NULL;
  }
  k = (Keys *)malloc(sizeof(Keys));
  if (!k) {
    BN_clear_free(priv);
    BN_free(pub);
    return NULL;
  }
  k->private_key = priv;
  k->public_key = pub;
  return k;
};

Frame *gen_hello_msg(Keys *k) {
  if (!k || !k->public_key)
    return NULL;
  uint8_t *payload = malloc(DH_PUB_LEN);
  if (!payload)
    return NULL;
  int res = BN_bn2binpad(k->public_key, payload, DH_PUB_LEN);
  if (res < 0) {
    free(payload);
    return NULL;
  }
  Frame *f = malloc(sizeof(Frame));
  if (!f) {
    free(payload);
    return NULL;
  }
  f->type = MSG_HELLO;
  f->len = DH_PUB_LEN;
  f->payload = payload;
  return f;
};

int do_handshake_client(int fd, Keys *k, D_Keys *dk) {
  if (!k)
    return -1;
  int rc = -1;
  Frame *hello_out = NULL;
  Frame hello_in = {0};
  Frame out = {0};
  BIGNUM *peer_pub = NULL;
  BIGNUM *shared_secret = NULL;
  D_Keys *dkey = NULL;
  uint8_t salt[2 * DH_PUB_LEN] = {0};
  // send our HELLO (public key) to the server
  hello_out = gen_hello_msg(k);
  if (!hello_out || send_frame(fd, hello_out) == -1) {
    goto cleanup;
  }
  // receive the server's HELLO and check type and length
  if (recv_frame(fd, &hello_in) == -1) {
    goto cleanup;
  }
  if (hello_in.type != MSG_HELLO || hello_in.len != DH_PUB_LEN) {
    goto cleanup;
  }
#ifdef CSL_TAMPER
#if CSL_TAMPER == 1
  hello_in.payload[DH_PUB_LEN - 1] ^=
      0x01; // flip one bit of the server's public value
#elif CSL_TAMPER == 2
  memset(hello_in.payload, 0,
         DH_PUB_LEN); // replace it with the value 1 (invalid)
  hello_in.payload[DH_PUB_LEN - 1] = 1;
#endif
#endif
  // bytes -> BIGNUM (allocates it for us), then validate
  peer_pub = BN_bin2bn(hello_in.payload, hello_in.len, NULL);
  if (!peer_pub || !valid_pub_key(peer_pub)) {
    goto cleanup;
  }
  int res = gen_salt(peer_pub, k->public_key, salt);
  if (!res) {
    goto cleanup;
  }
  shared_secret = dh_generate_shared(k->private_key, peer_pub);
  if (!shared_secret) {
    goto cleanup;
  }
  dkey = derive_keys(shared_secret, salt, 2 * DH_PUB_LEN);
  if (!dkey) {
    goto cleanup;
  }
  *dk = *dkey;
  uint8_t tag_c[KDF_LEN];
  res = gen_tag(dkey->client_mac_key, salt, 2 * DH_PUB_LEN, 12,
                (uint8_t *)"client sends", tag_c);
  if (!res) {
    goto cleanup;
  }
#ifdef CSL_TAMPER
#if CSL_TAMPER == 3
  tag_c[0] ^= 0x01; // corrupt one bit of the client's tag
#endif
#endif
  Frame fin = {MSG_FINISHED, KDF_LEN, tag_c};
  res = send_frame(fd, &fin);
  if (res < 0) {
    goto cleanup;
  }
  res = recv_frame(fd, &out);
  if (res < 0 || out.type != MSG_FINISHED || out.len != KDF_LEN) {
    goto cleanup;
  }
  uint8_t tag_s[KDF_LEN];
  res = gen_tag(dkey->server_mac_key, salt, 2 * DH_PUB_LEN, 12,
                (uint8_t *)"server sends", tag_s);
  if (!res) {
    goto cleanup;
  }
  if (CRYPTO_memcmp(tag_s, out.payload, KDF_LEN) != 0)
    goto cleanup;
  rc = 0;
cleanup:
  if (rc == -1) {
    uint8_t *p = (uint8_t *)"something went wrong,handshake not successfull";
    Frame er = {MSG_ALERT, strlen((char *)p), p};
    printf("failed\n");
    send_frame(fd, &er);
  }
  if (hello_out) {
    frame_free(hello_out);
    free(hello_out);
  }
  frame_free(&hello_in);
  frame_free(&out);
  BN_free(peer_pub);
  BN_clear_free(shared_secret);
  OPENSSL_clear_free(dkey, sizeof *dkey);
  OPENSSL_cleanse(salt, sizeof salt);
  cleanup_keys(k);
  return rc;
}

int do_handshake_server(int fd, Keys *k, D_Keys *dk) {
  if (!k)
    return -1;
  int rc = -1;
  Frame hello_in = {0};
  Frame out = {0};
  Frame *hello_out = NULL;
  BIGNUM *peer_pub = NULL;
  BIGNUM *shared_secret = NULL;
  D_Keys *dkey = NULL;
  uint8_t salt[2 * DH_PUB_LEN] = {0};
  // receive HELLO from the client and check type and length
  if (recv_frame(fd, &hello_in) == -1) {
    goto cleanup;
  }
  if (hello_in.type != MSG_HELLO || hello_in.len != DH_PUB_LEN) {
    goto cleanup;
  }
  // bytes -> BIGNUM, then validate
  peer_pub = BN_bin2bn(hello_in.payload, hello_in.len, NULL);
  if (!peer_pub || !valid_pub_key(peer_pub)) {
    goto cleanup;
  }
  int res = gen_salt(k->public_key, peer_pub, salt);
  if (!res) {
    goto cleanup;
  }
  shared_secret = dh_generate_shared(k->private_key, peer_pub);
  if (!shared_secret) {
    goto cleanup;
  }
  // send server HELLO to the client
  hello_out = gen_hello_msg(k);
  if (!hello_out || send_frame(fd, hello_out) == -1) {
    goto cleanup;
  }
  dkey = derive_keys(shared_secret, salt, 2 * DH_PUB_LEN);
  if (!dkey) {
    goto cleanup;
  }
  *dk = *dkey;
  res = recv_frame(fd, &out);
  if (res < 0 || out.type != MSG_FINISHED || out.len != KDF_LEN) {
    goto cleanup;
  }

  uint8_t tag_c[KDF_LEN];
  res = gen_tag(dkey->client_mac_key, salt, 2 * DH_PUB_LEN, 12,
                (uint8_t *)"client sends", tag_c);

  if (!res) {
    goto cleanup;
  }
  if (CRYPTO_memcmp(tag_c, out.payload, KDF_LEN) != 0)
    goto cleanup;
  uint8_t tag_s[KDF_LEN];
  res = gen_tag(dkey->server_mac_key, salt, 2 * DH_PUB_LEN, 12,
                (uint8_t *)"server sends", tag_s);
  if (!res) {
    goto cleanup;
  }
  Frame in = {MSG_FINISHED, KDF_LEN, tag_s};
  res = send_frame(fd, &in);
  if (res < 0) {
    goto cleanup;
  }
  rc = 0;
cleanup:
  if (rc == -1) {
    uint8_t *p = (uint8_t *)"something went wrong";
    printf("failed\n");
    Frame er = {MSG_ALERT, strlen((char *)p), p};
    send_frame(fd, &er);
  }
  if (hello_out) {
    frame_free(hello_out);
    free(hello_out);
  }
  frame_free(&hello_in);
  frame_free(&out);
  BN_free(peer_pub);
  BN_clear_free(shared_secret);
  OPENSSL_clear_free(dkey, sizeof *dkey);
  OPENSSL_cleanse(salt, sizeof salt);
  cleanup_keys(k);
  return rc;
}

int gen_salt(const BIGNUM *pub_server, const BIGNUM *pub_client,
             uint8_t *salt) {
  if (BN_bn2binpad(pub_server, salt, DH_PUB_LEN) != DH_PUB_LEN ||
      BN_bn2binpad(pub_client, salt + DH_PUB_LEN, DH_PUB_LEN) != DH_PUB_LEN) {
    return 0;
  }
  return 1;
}

D_Keys *derive_keys(const BIGNUM *shared_secret, uint8_t *salt, int size) {
  uint8_t sec[DH_PUB_LEN];
  uint8_t prk[KDF_LEN];
  D_Keys *keys = OPENSSL_zalloc(sizeof *keys);
  if (!keys)
    return NULL;
  // fixed-length encodings, so both sides feed identical bytes into the KDF
  if (BN_bn2binpad(shared_secret, sec, DH_PUB_LEN) != DH_PUB_LEN)
    goto fail;
  // extract: compress the secret into one 32-byte PRK, salted with both
  // public values
  if (kdf_extract(salt, size, sec, sizeof sec, prk) != 0)
    goto fail;
  // expand: one key per label
  if (kdf_expand(prk, "server_enc", keys->encryption_server) ||
      kdf_expand(prk, "client_enc", keys->encryption_client) ||
      kdf_expand(prk, "mac_auth_srv", keys->server_mac_key) ||
      kdf_expand(prk, "mac_auth_cli", keys->client_mac_key))
    goto fail;
  OPENSSL_cleanse(sec, sizeof sec);
  OPENSSL_cleanse(prk, sizeof prk);
  return keys;
fail:
  OPENSSL_cleanse(sec, sizeof sec);
  OPENSSL_cleanse(prk, sizeof prk);
  OPENSSL_clear_free(keys, sizeof *keys);
  return NULL;
}

int gen_tag(uint8_t *mac, uint8_t *salt, int salt_size, int info_size,
            uint8_t *info, uint8_t *tag) {
  uint8_t *fin = malloc(salt_size + info_size);
  if (fin == NULL) {
    return 0;
  }
  memcpy(fin, salt, salt_size);
  memcpy(fin + salt_size, info, info_size);
  int res = hmac_sha256(mac, KDF_LEN, fin, salt_size + info_size, tag);
  free(fin);
  if (res == -1) {
    return 0;
  }
  return 1;
}
