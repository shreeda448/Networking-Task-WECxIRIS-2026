#include "dh.h"
#include "config.h"
#include <openssl/bn.h>

static BIGNUM *s_p = NULL;
static BIGNUM *s_g = NULL;
static BN_CTX *s_ctx = NULL;

// Life time of variables
// private keys -> not useful after generation of shared secret key
// public keys are not useful after transcription is generated
// shared private key -> not useful after key derivation
// BN_clear_free -> a,b,shared private key
// BN_free -> public keys
// NOTE  : s_p and s_g are not useful after generation of public keys right
// now but it would be needed if I will cater to multiple clients using the
// same server
int dh_init(void) {
  if (s_p)
    return 0;
  s_ctx = BN_CTX_new();
  s_g = BN_new();
  if (!s_ctx || !s_g || !BN_set_word(s_g, DH_G_VALUE)) {
    goto fail;
  }
  if (!BN_hex2bn(&s_p, DH_P_HEX)) {
    goto fail;
  }
  if (BN_num_bits(s_p) != 2048) {
    goto fail;
  }
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

BIGNUM *dh_random_private(const BIGNUM *p) {
  BIGNUM *range = BN_dup(p);
  BIGNUM *priv = BN_new();
  if (!range || !priv)
    goto err;
  if (!BN_sub_word(range, 3))
    goto err; // range = p - 3
  if (BN_cmp(range, BN_value_one()) < 0)
    goto err; // p too small: need range >= 1
  if (!BN_priv_rand_range(priv, range))
    goto err; // [0, p-4]
  if (!BN_add_word(priv, 2))
    goto err; // [2, p-2]
  BN_free(range);
  return priv;
err:
  BN_free(range);
  BN_clear_free(priv);
  return NULL;
}

BIGNUM *dh_generate_private(void) {
  if (!dh_p())
    return NULL;
  return dh_random_private(dh_p());
}

BIGNUM *dh_generate_public(BIGNUM *priv) {
  BIGNUM *rr = BN_new();
  if (!dh_p() || !dh_g() || !priv || !rr || !s_ctx) {
    goto cleanup;
  }
  BN_set_flags(priv, BN_FLG_CONSTTIME);
  int res = BN_mod_exp_mont_consttime(rr, dh_g(), priv, dh_p(), s_ctx, NULL);
  if (res == 1) {
    return rr;
  } else {
    goto cleanup;
  }
cleanup:
  BN_free(rr);
  rr = NULL;
  return rr;
}

void cleanup_keys(Keys *k) {
  if (k == NULL)
    return;
  BN_clear_free(k->private_key);
  k->private_key = NULL;
  BN_free(k->public_key);
  k->public_key = NULL;
}

int valid_priv_key(BIGNUM *priv) {
  if (!priv || !dh_p())
    return 0;
  BIGNUM *max = BN_dup(dh_p());
  if (!max)
    return 0;
  int is_valid = 0;
  if (!BN_sub_word(max, 2))
    goto cleanup;
  // Check: 2 <= priv <= p - 2
  if (BN_cmp(priv, BN_value_one()) > 0 && BN_cmp(priv, max) <= 0) {
    is_valid = 1;
  }

cleanup:
  BN_free(max);
  return is_valid;
}

int valid_pub_key(BIGNUM *pub) {
  if (!pub || !dh_p() || BN_is_negative(pub))
    return 0;
  // Check: pub > 1
  if (BN_cmp(pub, BN_value_one()) <= 0)
    return 0;
  BIGNUM *p_minus_one = BN_dup(dh_p());
  if (!p_minus_one)
    return 0;
  BN_sub_word(p_minus_one, 1);
  // Check: pub < p - 1  (which means pub <= p - 2)
  int ok = (BN_cmp(pub, p_minus_one) < 0);
  BN_free(p_minus_one);
  return ok;
}

BIGNUM *dh_generate_shared(BIGNUM *priv, BIGNUM *pub) {
  BIGNUM *rr = BN_new();
  if (!pub || !priv || !dh_p()) {
    goto cleanup;
  }
  BN_set_flags(priv, BN_FLG_CONSTTIME);
  int res = BN_mod_exp_mont_consttime(rr, pub, priv, dh_p(), s_ctx, NULL);
  if (res == 1) {
    return rr;
  } else {
    goto cleanup;
  }
cleanup:
  BN_free(rr);
  rr = NULL;
  return rr;
};
