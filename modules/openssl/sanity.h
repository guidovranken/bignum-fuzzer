#ifndef BIGNUM_FUZZER_OPENSSL_SANITY_H
#define BIGNUM_FUZZER_OPENSSL_SANITY_H
#include <openssl/bn.h>
void test_bignum_sanity(const BIGNUM* bignum);
void test_bn_mont_ctx_sanity(const BN_MONT_CTX* bn_mont_ctx);
#ifndef BIGNUM_FUZZER_BORINGSSL
void test_bn_recp_ctx_sanity(const BN_RECP_CTX* bn_recp_ctx);
#endif
#endif
