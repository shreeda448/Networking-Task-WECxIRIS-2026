#include "assert.h"
#include "config.h"
#include "dh.h"
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <stdio.h>

void test_p_bits() { assert(BN_num_bits(dh_p()) == 2048); }
void test_prime_p() { assert(BN_check_prime(dh_p(), NULL, NULL)); }

int main(void) {
  dh_init();
  printf("%s\n", OpenSSL_version(OPENSSL_VERSION));
  BIGNUM *x = BN_new();
  BN_set_word(x, 42);
  char *s = BN_bn2dec(x);
  printf("%s\n", s);
  OPENSSL_free(s);
  BN_free(x);
  test_p_bits();
  puts("p_bits: ok");
  test_prime_p();
  puts("prime_p: ok");
  dh_cleanup();
  return 0;
}
