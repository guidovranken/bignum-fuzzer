#ifdef TEST_STRUCT_SANITY
#include <openssl/bn.h>
#include "sanity.h"
struct bignum_st {
    BN_ULONG *d;                /* Pointer to an array of 'BN_BITS2' bit
                                 * chunks. */
    int top;                    /* Index of last used d +1. */
    /* The next are internal book keeping for bn_expand. */
    int dmax;                   /* Size of the d array. */
    int neg;                    /* one if the number is negative */
    int flags;
};

void test_bignum_sanity(const BIGNUM* bignum)
{
    if ( bignum->d != NULL ) {
        BN_ULONG d = *(bignum->d);
    }
    if ( bignum->top < 0 ) abort();
    if ( bignum->dmax < 0 ) abort();
    if ( bignum->neg != 0 && bignum->neg != 1 ) abort();
}

struct bn_mont_ctx_st {
    int ri;                     /* number of bits in R */
    BIGNUM RR;                  /* used to convert to montgomery form */
    BIGNUM N;                   /* The modulus */
    BIGNUM Ni;                  /* R*(1/R mod N) - N*Ni = 1 (Ni is only
                                 * stored for bignum algorithm) */
    BN_ULONG n0[2];             /* least significant word(s) of Ni; (type
                                 * changed with 0.9.9, was "BN_ULONG n0;"
                                 * before) */
    int flags;
};

void test_bn_mont_ctx_sanity(const BN_MONT_CTX* bn_mont_ctx)
{
    if ( bn_mont_ctx->ri < 0 ) abort();
    test_bignum_sanity(&(bn_mont_ctx->RR));
    test_bignum_sanity(&(bn_mont_ctx->N));
    test_bignum_sanity(&(bn_mont_ctx->Ni));
}

struct bn_recp_ctx_st {
    BIGNUM N;                   /* the divisor */
    BIGNUM Nr;                  /* the reciprocal */
    int num_bits;
    int shift;
    int flags;
};

void test_bn_recp_ctx_sanity(const BN_RECP_CTX* bn_recp_ctx)
{
    test_bignum_sanity(&(bn_recp_ctx->N));
    test_bignum_sanity(&(bn_recp_ctx->Nr));
    if ( bn_recp_ctx->num_bits < 0 ) abort();
    if ( bn_recp_ctx->shift < 0 ) abort();
}
#else /* !TEST_STRUCT_SANITY */
#define test_bignum_sanity(...)
#define test_bn_mont_ctx_sanity(...)
#define test_bn_recp_ctx_sanity(...)
#endif /* TEST_STRUCT_SANITY */
