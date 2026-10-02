#include "handshake.h"
#include "frame.h"
#include <openssl/bn.h>
#include <sched.h>
#include <stdint.h>

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

  BN_print_fp(stdout, shared_secret);
  printf("\n");
  // TODO: remove the free statement of shared_secret in later levels
  BN_clear_free(shared_secret);
  BN_free(ret);
  // TODO: generate transcript and derived keys: for this i need the public keys
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
  BN_print_fp(stdout, shared_secret);
  printf("\n");
  // TODO: remove the free statement of shared_secret in later levels
  BN_clear_free(shared_secret);
  BN_free(ret);
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
  // TODO: generate transcript and derived keys: for this i need the public keys
  return 0;
};
