#include "handshake.h"
#include "dh.h"
#include "frame.h"
#include "kdf.h"
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <string.h>

// just a temperory helper to print hex
static void print_hex(const char *label, const uint8_t *data, size_t len) {
  printf("%s: ", label);
  for (size_t i = 0; i < len; i++) {
    printf("%02X", data[i]);
  }
  printf("\n");
}

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

int do_handshake_client(int fd, Keys *k) {
  if (!k)
    return -1;
  int rc = -1;
  Frame *hello_out = NULL;
  Frame hello_in = {0};
  BIGNUM *peer_pub = NULL;
  BIGNUM *shared_secret = NULL;
  D_Keys *dkey = NULL;
  // send our HELLO (public key) to the server
  hello_out = gen_hello_msg(k);
  if (!hello_out || send_frame(fd, hello_out) == -1)
    goto cleanup;
  // receive the server's HELLO and check type and length
  if (recv_frame(fd, &hello_in) == -1)
    goto cleanup;
  if (hello_in.type != MSG_HELLO || hello_in.len != DH_PUB_LEN)
    goto cleanup;
  // bytes -> BIGNUM (allocates it for us), then validate
  peer_pub = BN_bin2bn(hello_in.payload, hello_in.len, NULL);
  if (!peer_pub || !valid_pub_key(peer_pub))
    goto cleanup;
  shared_secret = dh_generate_shared(k->private_key, peer_pub);
  if (!shared_secret)
    goto cleanup;
  dkey = derive_keys(shared_secret, peer_pub, k->public_key);
  if (!dkey)
    goto cleanup;
  print_hex("encryption_client", dkey->encryption_client, 32);
  print_hex("encryption_server", dkey->encryption_server, 32);
  print_hex("client_mac_key", dkey->client_mac_key, 32);
  print_hex("server_mac_key", dkey->server_mac_key, 32);
  rc = 0;
cleanup:
  if (hello_out) {
    frame_free(hello_out);
    free(hello_out);
  }
  frame_free(&hello_in);
  BN_free(peer_pub);
  BN_clear_free(shared_secret);
  OPENSSL_clear_free(dkey, sizeof *dkey);
  cleanup_keys(k);
  return rc;
}

int do_handshake_server(int fd, Keys *k) {
  if (!k)
    return -1;
  int rc = -1;
  Frame hello_in = {0};
  Frame *hello_out = NULL;
  BIGNUM *peer_pub = NULL;
  BIGNUM *shared_secret = NULL;
  D_Keys *dkey = NULL;
  // receive HELLO from the client and check type and length
  if (recv_frame(fd, &hello_in) == -1)
    goto cleanup;
  if (hello_in.type != MSG_HELLO || hello_in.len != DH_PUB_LEN)
    goto cleanup;
  // bytes -> BIGNUM, then validate
  peer_pub = BN_bin2bn(hello_in.payload, hello_in.len, NULL);
  if (!peer_pub || !valid_pub_key(peer_pub))
    goto cleanup;
  shared_secret = dh_generate_shared(k->private_key, peer_pub);
  if (!shared_secret)
    goto cleanup;
  // send server HELLO to the client
  hello_out = gen_hello_msg(k);
  if (!hello_out || send_frame(fd, hello_out) == -1)
    goto cleanup;
  dkey = derive_keys(shared_secret, k->public_key, peer_pub);
  if (!dkey)
    goto cleanup;
  print_hex("encryption_client", dkey->encryption_client, 32);
  print_hex("encryption_server", dkey->encryption_server, 32);
  print_hex("client_mac_key", dkey->client_mac_key, 32);
  print_hex("server_mac_key", dkey->server_mac_key, 32);
  rc = 0;
cleanup:
  if (hello_out) {
    frame_free(hello_out);
    free(hello_out);
  }
  frame_free(&hello_in);
  BN_free(peer_pub);
  BN_clear_free(shared_secret);
  OPENSSL_clear_free(dkey, sizeof *dkey);
  cleanup_keys(k);
  return rc;
}

D_Keys *derive_keys(const BIGNUM *shared_secret, const BIGNUM *pub_server,
                    const BIGNUM *pub_client) {
  uint8_t sec[DH_PUB_LEN];
  uint8_t salt[2 * DH_PUB_LEN];
  uint8_t prk[KDF_LEN];
  D_Keys *keys = OPENSSL_zalloc(sizeof *keys);
  if (!keys)
    return NULL;
  // fixed-length encodings, so both sides feed identical bytes into the KDF
  if (BN_bn2binpad(shared_secret, sec, DH_PUB_LEN) != DH_PUB_LEN ||
      BN_bn2binpad(pub_server, salt, DH_PUB_LEN) != DH_PUB_LEN ||
      BN_bn2binpad(pub_client, salt + DH_PUB_LEN, DH_PUB_LEN) != DH_PUB_LEN)
    goto fail;
  // extract: compress the secret into one 32-byte PRK, salted with both public
  // values
  if (kdf_extract(salt, sizeof salt, sec, sizeof sec, prk) != 0)
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
