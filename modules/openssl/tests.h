#ifndef BIGNUM_FUZZER_OPENSSL_TESTS_H
#define BIGNUM_FUZZER_OPENSSL_TESTS_H
#include <openssl/bn.h>
void test_bn_sqrx8x_internal(const BIGNUM *B, const BIGNUM *C);
void test_rsaz_1024_mul_avx2(const BIGNUM* A, const BIGNUM *B, const BIGNUM *C);
void test_BN_mod_sqrt(const BIGNUM *B, const BIGNUM *C);
void test_SRP(const BIGNUM *A, const BIGNUM *B);
void test_BN_mod_inverse(const BIGNUM *B, const BIGNUM *C);
void test_RSA_public_encrypt(const BIGNUM *B, const BIGNUM *C, const BIGNUM *D);
#endif
