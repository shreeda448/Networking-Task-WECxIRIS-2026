#ifndef CSL_HANDSHAKE_H
#define CSL_HANDSHAKE_H
#include "dh.h"
#include "frame.h"
#include <openssl/bn.h>
#include <stdint.h>
Keys *gen_key_pair();
Frame *gen_hello_msg(Keys *k);
int do_handshake_client(int fd, Keys *k);
int do_handshake_server(int fd, Keys *k);
D_Keys *derive_keys(const BIGNUM *shared_secret, uint8_t *salt, int size);
int gen_salt(const BIGNUM *pub_server, const BIGNUM *pub_client, uint8_t *salt);
int gen_tag(uint8_t *mac, uint8_t *salt, int salt_size, int info_size,
            uint8_t *info, uint8_t *tag);
#endif
