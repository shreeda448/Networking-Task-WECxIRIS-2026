#include "dh.h"
#include <assert.h>
#include <openssl/bn.h>
#include <stdio.h>

// check 2048 bits in p

static void test_p_bits(void) { assert(BN_num_bits(dh_p()) == 2048); }

// check p is prime

static void test_p_prime(void) {
  assert(BN_check_prime(dh_p(), NULL, NULL) ==
         1); // 1 prime, 0 composite, -1 error
}

// check p is a safe prime or not

static void test_p_safe_prime(void) { // q = (p - 1) / 2 must be prime too
  BIGNUM *q = BN_dup(dh_p());
  assert(q != NULL);
  int ok = BN_sub_word(q, 1) && BN_rshift1(q, q);
  assert(ok);
  assert(BN_check_prime(q, NULL, NULL) == 1);
  BN_free(q);
}

// check the rand value is in range

static void test_priv_in_range(void) {
  BIGNUM *max = BN_dup(dh_p());
  assert(max != NULL);
  int ok = BN_sub_word(max, 2); // max = p - 2
  assert(ok);
  for (int i = 0; i < 100; i++) {
    BIGNUM *a = dh_generate_private();
    assert(a != NULL);
    assert(BN_cmp(a, BN_value_one()) > 0); // a > 1, so a >= 2
    assert(BN_cmp(a, max) <= 0);           // a <= p - 2
    BN_clear_free(a); // clear and free bcoz it is private key
  }
  BN_free(max);
}

// check private keys are distint for small values

static void test_priv_distinct(void) {
  BIGNUM *k[100];
  for (int i = 0; i < 100; i++) {
    k[i] = dh_generate_private();
    assert(k[i] != NULL);
  }
  for (int i = 0; i < 100; i++)
    for (int j = i + 1; j < 100; j++)
      assert(BN_cmp(k[i], k[j]) != 0);
  for (int i = 0; i < 100; i++)
    BN_clear_free(k[i]);
}

// check if about half should use  all 2048 bits

static void test_priv_top_bit(void) {
  int full = 0;
  for (int i = 0; i < 200; i++) {
    BIGNUM *a = dh_generate_private();
    assert(a != NULL);
    if (BN_num_bits(a) == 2048)
      full++;
    BN_clear_free(a);
  }
  assert(full > 60 && full < 140);
}

static void test_priv_boundaries_small_p(void) {
  BIGNUM *p = BN_new();
  assert(p != NULL);
  int ok = BN_set_word(p, 23); // valid private values: 2..21
  assert(ok);
  int seen[23] = {0};
  for (int i = 0; i < 10000; i++) {
    BIGNUM *a = dh_random_private(p);
    assert(a != NULL);
    BN_ULONG v = BN_get_word(a);
    assert(v >= 2 && v <= 21);
    seen[v]++;
    BN_clear_free(a);
  }
  for (int v = 2; v <= 21; v++)
    assert(seen[v] >
           0); // both ends (2 and 21) and everything in between is reachable
  BN_set_word(p, 3); // p - 3 = 0: no valid private values, must fail cleanly
  assert(dh_random_private(p) == NULL);
  BN_free(p);
}

static void test_priv_before_init(void) {
  dh_cleanup();
  assert(dh_generate_private() == NULL);
  int rc = dh_init();
  assert(rc == 0);
}

int main(void) {
  int rc = dh_init();
  assert(rc == 0);
  test_p_bits();
  puts("p_bits: ok");
  test_p_prime();
  puts("p_prime: ok");
  test_p_safe_prime();
  puts("p_safe_prime: ok");
  test_priv_in_range();
  puts("priv_in_range: ok");
  test_priv_distinct();
  puts("priv_distinct: ok");
  test_priv_top_bit();
  puts("priv_top_bit: ok");
  test_priv_boundaries_small_p();
  puts("priv_boundaries_small_p: ok");
  test_priv_before_init();
  puts("priv_before_init: ok");
  dh_cleanup();
  return 0;
}
