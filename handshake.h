#include "dh.h"
#include "frame.h"
#include <openssl/bn.h>
Keys *gen_key_pair();
Frame *gen_hello_msg(Keys *k);
int do_handshake_client(int fd, Keys *k);
int do_handshake_server(int fd, Keys *k);
D_Keys *derive_keys(BIGNUM *shared_secret, BIGNUM *pub_server,
                    BIGNUM *pub_client);
