#include <openssl/bn.h>
#include <stdint.h>
#include "tests.h"
#include "sanity.h"

extern BN_CTX *ctx;
extern BIGNUM *zero, *thousand;

int operation_ADD(BIGNUM* A, const BIGNUM* B, const BIGNUM* C, const BIGNUM* D, const uint8_t opt)
{
    return BN_add(A, B, C) != 1 ? -1 : 0;
}

int operation_SUB(BIGNUM* A, const BIGNUM* B, const BIGNUM* C, const BIGNUM* D, const uint8_t opt)
{
    return BN_sub(A, B, C) != 1 ? -1 : 0;
}

int operation_MUL(BIGNUM* A, const BIGNUM* B, const BIGNUM* C, const BIGNUM* D, const uint8_t opt)
{
    return BN_mul(A, B, C, ctx) != 1 ? -1 : 0;
}

int operation_DIV(BIGNUM* A, const BIGNUM* B, const BIGNUM* C, const BIGNUM* D, const uint8_t opt)
{
    int ret = -1;

    if ( BN_cmp(C, zero) != 0 ) {
        BIGNUM* rem = BN_new();
        BN_RECP_CTX *recp;

        if ( opt % 2 == 0 ) {
            ret = BN_div(A, rem, B, C, ctx) != 1 ? -1 : 0;
        } else {
            recp = BN_RECP_CTX_new();
            BN_RECP_CTX_set(recp, C, ctx);
            ret = BN_div_recp(A, rem, B, recp, ctx) != 1 ? -1 : 0;
            BN_RECP_CTX_free(recp);
        }

        if ( ret == 0 ) {
            ret = BN_cmp(rem, zero) == 0 ? 0 : -1;
        }
        BN_free(rem);
    } else {
        ret = -1;
    }

    return ret;
}

int operation_MOD(BIGNUM* A, const BIGNUM* B, const BIGNUM* C, const BIGNUM* D, const uint8_t opt)
{
    int ret = -1;

    if ( opt & 2 ) {
        ret = BN_mod(A, B, C, ctx) != 1 ? -1 : 0;
    } else {
        /* "BN_mod() corresponds to BN_div() with dv set to NULL" */
        ret = BN_div(NULL, A, B, C, ctx) != 1 ? -1 : 0;
    }

    return ret;
}

int operation_EXP_MOD(BIGNUM* A, const BIGNUM* B, const BIGNUM* C, const BIGNUM* D, const uint8_t opt)
{
    /* Use first and last bits of opt to construct range [0..3] */
    const uint8_t which = (opt & 1 ? 1 : 0) + (opt & 128 ? 2 : 0);
    int ret = -1;

    switch ( which ) {
        case    0:
            ret = BN_mod_exp_mont_consttime(A, B, C, D, ctx, NULL) != 1 ? -1 : 0;
            break;
        case    1:
            ret = BN_mod_exp_mont(A, B, C, D, ctx, NULL) != 1 ? -1 : 0;
            break;
        case    2:
            ret = BN_mod_exp(A, B, C, D, ctx) != 1 ? -1 : 0;
            break;
        case    3:
            ret = BN_mod_exp_simple(A, B, C, D, ctx) != 1 ? -1 : 0;
            break;
        default:
            /* Should't happen */
            abort();
            break;
    }

    return ret;
}

int operation_LSHIFT(BIGNUM* A, const BIGNUM* B, const BIGNUM* C, const BIGNUM* D, const uint8_t opt)
{
    if ( (opt % 2) == 0 ) {
        return BN_lshift(A, B, 1) != 1 ? -1 : 0;
    } else {
        return BN_lshift1(A, B) != 1 ? -1 : 0;
    }
}

int operation_RSHIFT(BIGNUM* A, const BIGNUM* B, const BIGNUM* C, const BIGNUM* D, const uint8_t opt)
{
    if ( (opt % 2) == 0 ) {
        return BN_rshift(A, B, 1) != 1 ? -1 : 0;
    } else {
        return BN_rshift1(A, B) != 1 ? -1 : 0;
    }
}

int operation_GCD(BIGNUM* A, const BIGNUM* B, const BIGNUM* C, const BIGNUM* D, const uint8_t opt)
{
    return BN_gcd(A, B, C, ctx) != 1 ? -1 : 0;
}

int operation_MOD_ADD(BIGNUM* A, const BIGNUM* B, const BIGNUM* C, const BIGNUM* D, const uint8_t opt)
{
    /* Use first and last bits of opt to construct range [0..3] */
    const uint8_t which = (opt & 1 ? 1 : 0) + (opt & 128 ? 2 : 0);
    int ret = -1;

    switch ( which ) {
        case    0:
            ret = BN_mod_add(A, B, C, D, ctx) != 1 ? -1 : 0;
            break;
        case    1:
            /* "... may be used if both a and b are non-negative and less than m" */
            if (    BN_cmp(B, zero) >= 0 &&
                    BN_cmp(C, zero) >= 0 &&
                    BN_cmp(B, D) < 0 &&
                    BN_cmp(C, D) < 0) {
                ret = BN_mod_add_quick(A, B, C, D) != 1 ? -1 : 0;
            } else {
                ret = -1;
            }
            break;
        default:
            ret = -1;
            break;
    }

    return ret;
}

int operation_EXP(BIGNUM* A, const BIGNUM* B, const BIGNUM* C, const BIGNUM* D, const uint8_t opt)
{
    int ret = -1;

    if ( BN_cmp(B, zero) > 0 && BN_ucmp(B, thousand) <= 0 && BN_cmp(C, zero) > 0 && BN_ucmp(C, thousand) <= 0 ) {
        ret = BN_exp(A, B, C, ctx) != 1 ? -1 : 0;
    } else {
        ret = -1;
    }

    return ret;
}

int operation_CMP(BIGNUM* A, const BIGNUM* B, const BIGNUM* C, const BIGNUM* D, const uint8_t opt)
{
    int c = BN_cmp(B, C);

    if ( c >= 0 ) {
        BN_set_word(A, c);
    } else {
        BN_set_word(A, 1);
        BN_set_negative(A, 1);
    }

    return 0;
}

int operation_SQR(BIGNUM* A, const BIGNUM* B, const BIGNUM* C, const BIGNUM* D, const uint8_t opt)
{
    return BN_sqr(A, B, ctx) != 1 ? -1 : 0;
}

int operation_NEG(BIGNUM* A, const BIGNUM* B, const BIGNUM* C, const BIGNUM* D, const uint8_t opt)
{
    return BN_sub(A, zero, B) != 1 ? -1 : 0;
}

int operation_ABS(BIGNUM* A, const BIGNUM* B, const BIGNUM* C, const BIGNUM* D, const uint8_t opt)
{
    int ret = -1;

    if ( BN_cmp(B, zero) < 0 ) {
        if ( opt & 1 ) {
            ret = BN_sub(A, zero, B) != 1 ? -1 : 0;
        } else {
            /* Another way to invert the sign of B */
            ret = (BN_sub(A, B, B) != 0 && BN_sub(A, A, B) != 0) ? 0 : -1;
        }
    } else {
        /* B is already a positive value */
        BN_copy(A, B);
        ret = 0;
    }

    return ret;
}

int operation_IS_PRIME(BIGNUM* A, const BIGNUM* B, const BIGNUM* C, const BIGNUM* D, const uint8_t opt)
{
    int ret = BN_is_prime_ex(B, 0, NULL, NULL);

    switch ( ret ) {
        case 0:
            BN_set_word(A, 0);
            ret = 0;
            break;
        case 1:
            BN_set_word(A, 1);
            ret = 0;
            break;
        default:
            ret = -1;
            break;
    }

    return ret;
}

int operation_MOD_SUB(BIGNUM* A, const BIGNUM* B, const BIGNUM* C, const BIGNUM* D, const uint8_t opt)
{
    /* Use first and last bits of opt to construct range [0..3] */
    const uint8_t which = (opt & 1 ? 1 : 0) + (opt & 128 ? 2 : 0);
    int ret = -1;

    switch ( which ) {
        case    0:
            ret = BN_mod_sub(A, B, C, D, ctx) != 1 ? -1 : 0;
            break;
        case    1:
            /* "... may be used if both a and b are non-negative and less than m" */
            if (    BN_cmp(B, zero) >= 0 &&
                    BN_cmp(C, zero) >= 0 &&
                    BN_cmp(B, D) < 0 &&
                    BN_cmp(C, D) < 0) {
                ret = BN_mod_sub_quick(A, B, C, D) != 1 ? -1 : 0;
            } else {
                ret = -1;
            }
            break;
        default:
            ret = -1;
            break;
    }

    return ret;
}

int operation_SWAP(BIGNUM* A, BIGNUM* B, const BIGNUM* C, const BIGNUM* D, const uint8_t opt)
{
    BN_swap(A, B);
    return 0;
}

int operation_MOD_MUL(BIGNUM* A, const BIGNUM* B, const BIGNUM* C, const BIGNUM* D, const uint8_t opt)
{
    int ret = -1;

    switch ( opt % 3 )
    {
        case    0:
            ret = BN_mod_mul(A, B, C, D, ctx) != 1 ? -1 : 0;
            break;
        case    1:
            {
                BN_RECP_CTX *recp = BN_RECP_CTX_new();
                test_bn_recp_ctx_sanity(recp);
                BN_RECP_CTX_set(recp, D, ctx);
                test_bn_recp_ctx_sanity(recp);
                ret = BN_mod_mul_reciprocal(A, B, C, recp, ctx) != 1 ? -1 : 0;
                if ( ret == 0 ) {
                    test_bn_recp_ctx_sanity(recp);
                }
                BN_RECP_CTX_free(recp);
                if ( ret == 0 ) {
                    /* D_abs = abs(D) */
                    BIGNUM* D_abs = BN_new();
                    if ( BN_copy(D_abs, D) != NULL ) {
                        if ( BN_cmp(D, zero) < 0 ) {
                            ret = BN_sub(D_abs, zero, D) != 1 ? -1 : 0;
                        }
                        if ( ret == 0 ) {
                            /* A = A + abs(D) */
                            ret = BN_add(A, A, D_abs) != 1 ? -1 : 0;
                            if ( ret == 0 ) {
                                /* A = A mod abs(D) */
                                ret = BN_mod(A, A, D_abs, ctx) != 1 ? -1 : 0;
                            }
                        }
                        BN_free(D_abs);
                    } else {
                        ret = -1;
                    }
                }
            }
            break;
        case 2:
            {
                BN_MONT_CTX* mont = BN_MONT_CTX_new();
                ret = BN_MONT_CTX_set(mont, D, ctx) != 1 ? -1 : 0;
                if ( ret == 0 ) {
                    BIGNUM *b, *c, *_b, *_c;
                    test_bn_mont_ctx_sanity(mont);
                    _b = BN_dup(B);
                    _c = BN_dup(C);
                    b = BN_new();
                    c = BN_new();
                    BN_nnmod(_b, _b, D, ctx);
                    BN_nnmod(_c, _c, D, ctx);
                    BN_to_montgomery(b, _b, mont, ctx);
                    test_bn_mont_ctx_sanity(mont);
                    BN_to_montgomery(c, _c, mont, ctx);
                    test_bn_mont_ctx_sanity(mont);
                    ret = BN_mod_mul_montgomery(A, b, c, mont, ctx) != 1 ? -1 : 0;
                    if ( ret == 0 ) {
                        test_bn_mont_ctx_sanity(mont);
                        ret = BN_from_montgomery(A, A, mont, ctx) != 1 ? -1 : 0;
                        if ( ret == 0 ) {
                            test_bn_mont_ctx_sanity(mont);
                        }
                    }
                    BN_free(_b);
                    BN_free(_c);
                    BN_free(b);
                    BN_free(c);
                }
                BN_MONT_CTX_free(mont);
            }
            break;
    }

    return ret;
}

int operation_SET_BIT(BIGNUM* A, const BIGNUM* B, const BIGNUM* C, const BIGNUM* D, const uint8_t opt)
{
    int ret = -1;
    if ( BN_cmp(B, thousand) <= 0 && BN_cmp(B, zero) >= 0 ) {
        const char* res = BN_bn2dec(B);
        if ( res != NULL ) {
            long strtol(const char *nptr, char **endptr, int base);
            long N = strtol(res, NULL, 10);
            if ( N >= 0 ) {
                ret = BN_set_bit(A, N) != 1 ? -1 : 0;
            }
            OPENSSL_free((void*)res);
        }
    }

    return ret;
}

int operation_NOP(BIGNUM* A, const BIGNUM* B, const BIGNUM* C, const BIGNUM* D, const uint8_t opt)
{
    switch ( opt ) {
        case    0:
            test_bn_sqrx8x_internal(B, C);
            break;
        case    1:
            test_rsaz_1024_mul_avx2(A, B, C);
            break;
        case    2:
            test_BN_mod_sqrt(B, C);
            break;
        case    3:
            test_SRP(B, C);
            break;
        case    4:
            test_BN_mod_inverse(B, C);
            break;
        case    5:
            test_RSA_public_encrypt(B, C, D);
            break;
        default:
            break;
    }

    return 0;
}

