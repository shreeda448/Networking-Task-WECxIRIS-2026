#ifndef CSL_HANDSHAKE_H
#define CSL_HANDSHAKE_H
#include "dh.h"
#include "frame.h"
#include <openssl/bn.h>
Keys *gen_key_pair();
Frame *gen_hello_msg(Keys *k);
int do_handshake_client(int fd, Keys *k);
int do_handshake_server(int fd, Keys *k);
D_Keys *derive_keys(const BIGNUM *shared_secret, const BIGNUM *pub_server,
                    const BIGNUM *pub_client);
#endif
