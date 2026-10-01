#include "openssl/bn.h"
#define DH_PUB_LEN 256    // 2048 bits, big-endian on the wire
int dh_init(void);        // parse p and g, build a BN_CTX; 0 on success
void dh_cleanup(void);    // frees the memory of  these BIGNUM's
const BIGNUM *dh_p(void); // getters for  p and g;
const BIGNUM *dh_g(void);
