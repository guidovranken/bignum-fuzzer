#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/crypto.h>
#include <bnfuzz/module.h>
#include <bnfuzz/operation.h>
#include <bnfuzz/bignum.h>

static BN_CTX *ctx = NULL;
static BIGNUM *zero = NULL, *minone = NULL, *ten = NULL, *thousand = NULL;

static int initialize(void)
{
    if ( (ctx = BN_CTX_new()) == NULL ) {
        return -1;
    }
    zero = BN_new();
    BN_zero(zero);
    minone = BN_new();
    BN_set_word(minone, 1);
    BN_set_negative(minone, 1);
    ten = BN_new();
    BN_set_word(ten, 10);
    thousand = BN_new();
    BN_set_word(thousand, 1000);
    return 0;
}

static int bignum_from_string(const char* input, void** output)
{
    BIGNUM* bn = NULL;

    *output = NULL;

    if ( (bn = BN_new()) == NULL ) {
        goto error;
    }
    
    if ( BN_dec2bn(&bn, input) == 0 ) {
        goto error;
    }

    *((BIGNUM**)output) = bn;
    return 0;

error:
    BN_free(bn);
    
    return -1;
}

static int string_from_bignum(void* input, char** output)
{
    BIGNUM* bn = (BIGNUM*)input;
    const char* res = BN_bn2dec(bn);
    *output = NULL;
    if ( res == NULL ) {
        goto error;
    }
    *output = malloc(strlen(res)+1);
    memcpy(*output, res, strlen(res)+1);
    OPENSSL_free((void*)res);

    return 0;
error:
    free(*output);
    *output = NULL;
    return -1;
}

static void destroy_bignum(void* bignum)
{
    BIGNUM* bn = (BIGNUM*)bignum;

    if ( bn == NULL ) {
        return;
    }

    BN_free(bn);
}

static void test_bn_sqrx8x_internal(const BIGNUM *B, const BIGNUM *C)
{
    /* Test for bn_sqrx8x_internal carry bug on x86_64 (CVE-2017-3736) */
    if ( BN_cmp(C, B) >= 0 &&
            BN_cmp(B, zero) > 0 ) /* this automatically implies that C is also positive */ {
        BN_MONT_CTX* mont = BN_MONT_CTX_new();
        BIGNUM* Bcopy = BN_dup(B);
        if ( BN_MONT_CTX_set(mont, C, ctx) != 0 ) {
            BIGNUM* x = BN_new();
            if ( BN_mod_mul_montgomery(x, B, B, mont, ctx) != 0 ) {
                BIGNUM* y = BN_new();
                if ( BN_mod_mul_montgomery(y, B, Bcopy, mont, ctx) != 0 ) {
                    if ( BN_cmp(x, y) != 0 ) {
                        abort();
                    }
                }
                BN_free(y);
            }
            BN_free(x);
        }
        BN_MONT_CTX_free(mont);
        BN_free(Bcopy);
    }
}

static void test_rsaz_1024_mul_avx2(const BIGNUM* A, const BIGNUM *B, const BIGNUM *C)
{
    /* Test for rsaz_1024_mul_avx2 overflow bug on x86_64 (CVE-2017-3738) */
    if ( BN_cmp(C, zero) > 0 &&
            BN_cmp(B, zero) > 0 &&
            BN_cmp(A, zero) > 0 ) {
        BN_MONT_CTX* mont = BN_MONT_CTX_new();
        if ( BN_MONT_CTX_set(mont, C, ctx) != 0 ) {
            BIGNUM* x = BN_new();
            if ( BN_mod_exp_mont_consttime(x, A, B, C, ctx, mont) != 0 ) {
                BIGNUM* y = BN_new();
                if ( BN_mod_exp_mont(y, A, B, C, ctx, mont) != 0 ) {
                    if ( BN_cmp(x, y) != 0 ) {
                        abort();
                    }
                }
                BN_free(y);
            }
            BN_free(x);
        }
        BN_MONT_CTX_free(mont);
    }
}

static void test_BN_mod_sqrt(const BIGNUM *B, const BIGNUM *C)
{
    BIGNUM* tmp1 = BN_new();
    BIGNUM* tmp2 = BN_new();

    if ( BN_cmp(B, zero) < 0 || BN_cmp(C, zero) < 0 ) {
        goto end;
    }

    /* C must be prime */
    if ( BN_is_prime_ex(C, 0, NULL, NULL) != 1 ) {
        goto end;
    }

    if ( BN_mod_sqrt(tmp1, B, C, ctx) == NULL ) {
        goto end;
    }

    if ( BN_sqr(tmp1, tmp1, ctx) != 1 ) {
        goto end;
    }

    if ( BN_mod(tmp1, tmp1, C, ctx) != 1 ) {
        goto end;
    }

    if ( BN_copy(tmp2, B) == NULL ) {
        goto end;
    }

    if ( BN_mod(tmp2, tmp2, C, ctx) != 1 ) {
        goto end;
    }

    /* tmp1 and tmp2 must be the same */

    if ( BN_cmp(tmp1, tmp2) != 0 ) {
        abort();
    }

end:
	BN_free(tmp1);
	BN_free(tmp2);
}

static int operation(
        bignum_cluster_t* bignum_cluster,
        operation_t operation,
        uint8_t opt)
{
    int ret;
    BIGNUM *A, *B, *C, *D;

    A = (BIGNUM*)bignum_cluster->BN[0];
    B = (BIGNUM*)bignum_cluster->BN[1];
    C = (BIGNUM*)bignum_cluster->BN[2];
    D = (BIGNUM*)bignum_cluster->BN[3];

    bool f_constant_time = opt & 1 ? true : false;

    if ( operation != BN_FUZZ_OP_SWAP ) {
        if ( opt & 2 && BN_cmp(B, C) == 0 ) {
            B = C;
        }

        if ( opt & 4 && BN_cmp(C, D) == 0 ) {
            C = D;
        }
    }
    if ( opt & 8 ) {
        BN_set_flags(A, BN_FLG_CONSTTIME);
    } else {
        BN_set_flags(A, 0);
    }

    if ( opt & 16 ) {
        BN_set_flags(B, BN_FLG_CONSTTIME);
    } else {
        BN_set_flags(B, 0);
    }

    if ( opt & 32 ) {
        BN_set_flags(C, BN_FLG_CONSTTIME);
    } else {
        BN_set_flags(C, 0);
    }

    if ( opt & 64 ) {
        BN_set_flags(D, BN_FLG_CONSTTIME);
    } else {
        BN_set_flags(D, 0);
    }

    switch ( operation ) {
        case    BN_FUZZ_OP_ADD:
            ret = BN_add(A, B, C) != 1 ? -1 : 0;
            break;
        case    BN_FUZZ_OP_SUB:
            ret = BN_sub(A, B, C) != 1 ? -1 : 0;
            break;
        case    BN_FUZZ_OP_MUL:
            ret = BN_mul(A, B, C, ctx) != 1 ? -1 : 0;
            break;
        case    BN_FUZZ_OP_DIV:
            if ( BN_cmp(C, zero) != 0 ) {
                BIGNUM* rem = BN_new();
                ret = BN_div(A, rem, B, C, ctx) != 1 ? -1 : 0;
                if ( ret == 0 ) {
                    ret = BN_cmp(rem, zero) == 0 ? 0 : -1;
                }
                BN_free(rem);
            } else {
                ret = -1;
            }
            break;
        case    BN_FUZZ_OP_MOD:
            if ( opt & 2 ) {
                ret = BN_mod(A, B, C, ctx) != 1 ? -1 : 0;
            } else {
                /* "BN_mod() corresponds to BN_div() with dv set to NULL" */
                ret = BN_div(NULL, A, B, C, ctx) != 1 ? -1 : 0;
            }
            break;
        case    BN_FUZZ_OP_EXP_MOD:
            {
                /* Use first and last bits of opt to construct range [0..3] */
                const uint8_t which = (opt & 1 ? 1 : 0) + (opt & 128 ? 2 : 0);

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
            }
            break;
        case    BN_FUZZ_OP_LSHIFT:
            ret = BN_lshift(A, B, 1) != 1 ? -1 : 0;
            break;
        case    BN_FUZZ_OP_RSHIFT:
            ret = BN_rshift(A, B, 1) != 1 ? -1 : 0;
            break;
        case    BN_FUZZ_OP_GCD:
            ret = BN_gcd(A, B, C, ctx) != 1 ? -1 : 0;
            break;
        case    BN_FUZZ_OP_MOD_ADD:
            {
                /* Use first and last bits of opt to construct range [0..3] */
                const uint8_t which = (opt & 1 ? 1 : 0) + (opt & 128 ? 2 : 0);

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
            }
            break;
        case    BN_FUZZ_OP_EXP:
            if ( BN_cmp(B, zero) > 0 && BN_ucmp(B, thousand) <= 0 && BN_cmp(C, zero) > 0 && BN_ucmp(C, thousand) <= 0 ) {
                ret = BN_exp(A, B, C, ctx) != 1 ? -1 : 0;
            } else {
                ret = -1;
            }
            break;
        case    BN_FUZZ_OP_CMP:
            {
                int c = BN_cmp(B, C);
                if ( c >= 0 ) {
                    BN_set_word(A, c);
                } else {
                    BN_set_word(A, 1);
                    BN_set_negative(A, 1);
                }
            }
            ret = 0;
            break;
        case    BN_FUZZ_OP_SQR:
            ret = BN_sqr(A, B, ctx) != 1 ? -1 : 0;
            break;
        case    BN_FUZZ_OP_NEG:
            ret = BN_sub(A, zero, B) != 1 ? -1 : 0;
            break;
        case    BN_FUZZ_OP_ABS:
            if ( BN_cmp(B, zero) < 0 ) {
                if ( opt & 2 ) {
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
            break;
        case    BN_FUZZ_OP_IS_PRIME:
            ret = BN_is_prime_ex(B, 0, NULL, NULL);
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
            break;
        case BN_FUZZ_OP_MOD_SUB:
            {
                /* Use first and last bits of opt to construct range [0..3] */
                const uint8_t which = (opt & 1 ? 1 : 0) + (opt & 128 ? 2 : 0);

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
            }
            break;
        case BN_FUZZ_OP_SWAP:
            BN_swap(A, B);
            ret = 0;
            break;
        case BN_FUZZ_OP_MOD_MUL:
            switch ( opt % 3 ) {
                case    0:
                    ret = BN_mod_mul(A, B, C, D, ctx) != 1 ? -1 : 0;
                    break;
                case    1:
                    {
                        BN_RECP_CTX *recp = BN_RECP_CTX_new();
                        BN_RECP_CTX_set(recp, D, ctx);
                        ret = BN_mod_mul_reciprocal(A, B, C, recp, ctx) != 1 ? -1 : 0;
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
                            _b = BN_dup(B);
                            _c = BN_dup(C);
                            b = BN_new();
                            c = BN_new();
                            BN_nnmod(_b, _b, D, ctx);
                            BN_nnmod(_c, _c, D, ctx);
                            BN_to_montgomery(b, _b, mont, ctx);
                            BN_to_montgomery(c, _c, mont, ctx);
                            ret = BN_mod_mul_montgomery(A, b, c, mont, ctx) != 1 ? -1 : 0;
                            if ( ret == 0 ) {
                                ret = BN_from_montgomery(A, A, mont, ctx) != 1 ? -1 : 0;
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
            break;
        case BN_FUZZ_OP_SET_BIT:
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
            break;
        case BN_FUZZ_OP_NOP:
            {
                ret = 0;
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
                    default:
                        break;
                }
            }
            break;
        default:
            ret = -1;
    }

    return ret;
}

static void shutdown(void)
{
    if ( ctx != NULL ) {
        BN_CTX_free(ctx);
    }
    BN_free(zero);
    zero = NULL;
    BN_free(minone);
    minone = NULL;
    BN_free(ten);
    ten = NULL;
    BN_free(thousand);
    thousand = NULL;
}

module_t mod_openssl = {
    .initialize = initialize,
    .bignum_from_string = bignum_from_string,
    .string_from_bignum = string_from_bignum,
    .destroy_bignum = destroy_bignum,
    .operation = operation,
    .shutdown = shutdown,
    .name = "OpenSSL"
};
