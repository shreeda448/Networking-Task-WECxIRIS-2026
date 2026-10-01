#include "dh.h"
#include "config.h"
#include <openssl/bn.h>

static BIGNUM *s_p = NULL;
static BIGNUM *s_g = NULL;
static BN_CTX *s_ctx = NULL;

int dh_init(void) {
  if (s_p)
    return 0;
  s_ctx = BN_CTX_new();
  s_g = BN_new();
  if (!s_ctx || !s_g || !BN_set_word(s_g, DH_G_VALUE))
    goto fail;
  if (!BN_hex2bn(&s_p, DH_P_HEX))
    goto fail;
  return 0;
fail:
  dh_cleanup();
  return -1;
}

void dh_cleanup(void) {
  BN_free(s_p);
  BN_free(s_g);
  BN_CTX_free(s_ctx);
  s_g = NULL;
  s_p = NULL;
  s_ctx = NULL;
}

const BIGNUM *dh_p(void) { return s_p; }
const BIGNUM *dh_g(void) { return s_g; }
