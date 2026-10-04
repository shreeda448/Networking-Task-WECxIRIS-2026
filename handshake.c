#include "handshake.h"
#include "frame.h"
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/kdf.h>
#include <sched.h>
#include <stdint.h>
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
  // send hello msg, public key to server
  if (!k) {
    return -1;
  }
  Frame *hello_msg_client = gen_hello_msg(k);
  if (!hello_msg_client) {
    cleanup_keys(k);
    return -1;
  }
  int res = send_frame(fd, hello_msg_client);
  // if frame was not sent
  if (res == -1) {
    frame_free(hello_msg_client);
    cleanup_keys(k);
    return -1;
  }
  // recieve hello msg, public key from server
  Frame hello_msg_server;
  res = recv_frame(fd, &hello_msg_server);
  // if frame was not recieved
  if (res == -1) {
    frame_free(hello_msg_client);
    cleanup_keys(k);
    return -1;
  }
  // if the recieved message is not of type HELLO or is trucated
  if (hello_msg_server.type != MSG_HELLO ||
      hello_msg_server.len != DH_PUB_LEN) {
    frame_free(&hello_msg_server);
    frame_free(hello_msg_client);
    cleanup_keys(k);
    return -1;
  }
  // convert the payload from bytes to BIGNUM
  BIGNUM *ret = BN_new();
  if (!BN_bin2bn(hello_msg_server.payload, hello_msg_server.len, ret)) {
    frame_free(&hello_msg_server);
    frame_free(hello_msg_client);
    cleanup_keys(k);
    BN_free(ret);
    return -1;
  };
  // validate the public key
  if (!valid_pub_key(ret)) {
    frame_free(&hello_msg_server);
    frame_free(hello_msg_client);
    cleanup_keys(k);
    BN_free(ret);
    return -1;
  }
  // generate the shared secret
  BIGNUM *shared_secret = dh_generate_shared(k->private_key, ret);
  if (!shared_secret) {
    frame_free(&hello_msg_server);
    frame_free(hello_msg_client);
    cleanup_keys(k);
    BN_free(ret);
    return -1;
  }

  D_Keys *dkey = derive_keys(shared_secret, ret, k->public_key);
  print_hex("encryption_client", dkey->encryption_client, 32);
  print_hex("encryption_server", dkey->encryption_server, 32);
  print_hex("client_mac_key", dkey->client_mac_key, 32);
  print_hex("server_mac_key", dkey->server_mac_key, 32);
  return 0;
};

int do_handshake_server(int fd, Keys *k) {
  if (!k) {
    return -1;
  }
  // recieve HELLO from the client
  Frame hello_from_client;
  int res = recv_frame(fd, &hello_from_client);
  if (res == -1) {
    frame_free(&hello_from_client);
    cleanup_keys(k);
    return -1;
  }
  // validate message type and payload length
  if (hello_from_client.type != MSG_HELLO ||
      hello_from_client.len != DH_PUB_LEN) {
    frame_free(&hello_from_client);
    cleanup_keys(k);
    return -1;
  }

  // convert the payload from bytes to BIGNUM
  BIGNUM *ret = BN_new();
  if (!BN_bin2bn(hello_from_client.payload, hello_from_client.len, ret)) {
    frame_free(&hello_from_client);
    cleanup_keys(k);
    BN_free(ret);
    return -1;
  };

  // validate the public key
  if (!valid_pub_key(ret)) {
    frame_free(&hello_from_client);
    cleanup_keys(k);
    BN_free(ret);
    return -1;
  }
  // generate shared_secret
  BIGNUM *shared_secret = dh_generate_shared(k->private_key, ret);
  if (!shared_secret) {
    frame_free(&hello_from_client);
    cleanup_keys(k);
    BN_free(ret);
    return -1;
  }
  // send HELLO to the client
  Frame *hello_to_client = gen_hello_msg(k);
  if (!hello_to_client) {
    frame_free(&hello_from_client);
    cleanup_keys(k);
    return -1;
  }
  res = send_frame(fd, hello_to_client);
  if (res == -1) {
    frame_free(&hello_from_client);
    frame_free(hello_to_client);
    cleanup_keys(k);
    return -1;
  }
  D_Keys *dkey = derive_keys(shared_secret, k->public_key, ret);
  print_hex("encryption_client", dkey->encryption_client, 32);
  print_hex("encryption_server", dkey->encryption_server, 32);
  print_hex("client_mac_key", dkey->client_mac_key, 32);
  print_hex("server_mac_key", dkey->server_mac_key, 32);
  return 0;
};

void short_hmac(const uint8_t *key, int key_len, const uint8_t *data,
                int data_len, uint8_t *out) {
  uint32_t out_len;
  // key = salt = public_key_client || public_key_server
  // data = shared_secret
  // *out = output buffer
  // out_len = number of bytes written
  HMAC(EVP_sha256(), key, key_len, data, data_len, out, &out_len);
}

D_Keys *derive_keys(BIGNUM *shared_secret, BIGNUM *pub_server,
                    BIGNUM *pub_client) {
  D_Keys *keys = malloc(sizeof(D_Keys));
  uint8_t sec[DH_PUB_LEN];
  uint8_t salt[2 * DH_PUB_LEN];
  BN_bn2binpad(shared_secret, sec, DH_PUB_LEN);
  BN_bn2binpad(pub_server, salt, DH_PUB_LEN);
  BN_bn2binpad(pub_client, salt + DH_PUB_LEN, DH_PUB_LEN);

  // 2. HKDF-Extract Phase: Hash the secret using the salt to get a 32-byte
  // PRK
  unsigned char prk[32];
  short_hmac(salt, 2 * DH_PUB_LEN, sec, DH_PUB_LEN, prk);

  // 3. HKDF-Expand Phase: Generate final keys using simple distinct labels
  const uint8_t *info_srv = (const uint8_t *)"server_enc";
  const uint8_t *info_cli = (const uint8_t *)"client_enc";
  const uint8_t *info_mac_srv = (const uint8_t *)"mac_auth_srv";
  const uint8_t *info_mac_cli = (const uint8_t *)"mac_auth_cli";
  short_hmac(prk, 32, info_srv, 10, keys->encryption_server);
  short_hmac(prk, 32, info_cli, 10, keys->encryption_client);
  short_hmac(prk, 32, info_mac_srv, strlen((const char *)info_mac_srv),
             keys->server_mac_key);
  short_hmac(prk, 32, info_mac_cli, strlen((const char *)info_mac_cli),
             keys->client_mac_key);
  return keys;
}
