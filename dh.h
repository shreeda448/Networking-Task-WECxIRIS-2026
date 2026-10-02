#include "openssl/bn.h"
#define DH_PUB_LEN 256    // 2048 bits, big-endian on the wire
int dh_init(void);        // parse p and g, build a BN_CTX; 0 on success
void dh_cleanup(void);    // frees the memory of  these BIGNUM's
const BIGNUM *dh_p(void); // getters for  p and g;
const BIGNUM *dh_g(void);
BIGNUM *dh_random_private(const BIGNUM *p);
BIGNUM *dh_generate_private(void);        // generate private key
BIGNUM *dh_generate_public(BIGNUM *priv); // generate public key
BIGNUM *dh_generate_shared(BIGNUM *priv, BIGNUM *pub);
typedef struct {
  BIGNUM *private_key;
  BIGNUM *public_key;
} Keys;

void cleanup_keys(Keys *k);

int valid_priv_key(BIGNUM *priv);
int valid_pub_key(BIGNUM *pub);
