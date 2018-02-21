#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/crypto.h>
#include <openssl/srp.h>
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

#ifdef TEST_STRUCT_SANITY
struct bignum_st {
    BN_ULONG *d;                /* Pointer to an array of 'BN_BITS2' bit
                                 * chunks. */
    int top;                    /* Index of last used d +1. */
    /* The next are internal book keeping for bn_expand. */
    int dmax;                   /* Size of the d array. */
    int neg;                    /* one if the number is negative */
    int flags;
};

static void test_bignum_sanity(const BIGNUM* bignum)
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

static void test_bn_mont_ctx_sanity(const BN_MONT_CTX* bn_mont_ctx)
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

static void test_bn_recp_ctx_sanity(const BN_RECP_CTX* bn_recp_ctx)
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

static void test_bn_sqrx8x_internal(const BIGNUM *B, const BIGNUM *C)
{
    /* Test for bn_sqrx8x_internal carry bug on x86_64 (CVE-2017-3736) */
    if ( BN_cmp(C, B) >= 0 &&
            BN_cmp(B, zero) > 0 ) /* this automatically implies that C is also positive */ {
        BN_MONT_CTX* mont = BN_MONT_CTX_new();
        BIGNUM* Bcopy = BN_dup(B);
        if ( BN_MONT_CTX_set(mont, C, ctx) != 0 ) {
            BIGNUM* x = BN_new();
            test_bn_mont_ctx_sanity(mont);
            if ( BN_mod_mul_montgomery(x, B, B, mont, ctx) != 0 ) {
                BIGNUM* y = BN_new();
                test_bn_mont_ctx_sanity(mont);
                if ( BN_mod_mul_montgomery(y, B, Bcopy, mont, ctx) != 0 ) {
                    test_bn_mont_ctx_sanity(mont);
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
            test_bn_mont_ctx_sanity(mont);
            if ( BN_mod_exp_mont_consttime(x, A, B, C, ctx, mont) != 0 ) {
                BIGNUM* y = BN_new();
                test_bn_mont_ctx_sanity(mont);
                if ( BN_mod_exp_mont(y, A, B, C, ctx, mont) != 0 ) {
                    test_bn_mont_ctx_sanity(mont);
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

static void test_SRP(const BIGNUM *A, const BIGNUM *B)
{
    BIGNUM *a = NULL;
    BIGNUM *b = NULL;

    BIGNUM *s = NULL;
    BIGNUM *v = NULL;

    BIGNUM *Apub = NULL;
    BIGNUM *Bpub = NULL;

    BIGNUM *Kclient = NULL;
    BIGNUM *Kserver = NULL;

    BIGNUM *u = NULL;
    BIGNUM *x = NULL;

    const SRP_gN *GN = NULL;

    int i;

    if ( BN_cmp(A, zero) < 0 || BN_cmp(B, zero) < 0 ) {
        return;
    }

    a = BN_dup(A);
    b = BN_dup(A);

    if ( a == NULL || b == NULL ) {
        goto end;
    }

    GN = SRP_get_default_gN("1024");
    if (GN == NULL) {
        goto end;
    }

    if (!SRP_create_verifier_BN("alice", "password", &s, &v, GN->N, GN->g)) {
        goto end;
    }

    Bpub = SRP_Calc_B(b, GN->N, GN->g, v);
    if (!SRP_Verify_B_mod_N(Bpub, GN->N)) {
        goto end;
    }

    Apub = SRP_Calc_A(a, GN->N, GN->g);
    if (!SRP_Verify_A_mod_N(Apub, GN->N)) {
        goto end;
    }

    u = SRP_Calc_u(Apub, Bpub, GN->N);
    x = SRP_Calc_x(s, "alice", "password");
    Kclient = SRP_Calc_client_key(GN->N, Bpub, GN->g, x, a, u);
    Kserver = SRP_Calc_server_key(Apub, v, u, b, GN->N);

    if (BN_cmp(Kclient, Kserver) != 0) {
        abort();
    }

end:
    BN_free(Kclient);
    BN_free(Kserver);
    BN_free(x);
    BN_free(u);
    BN_free(Apub);
    BN_free(Bpub);
    BN_free(s);
    BN_free(v);
    BN_free(a);
    BN_free(b);
}

static void test_BN_mod_inverse(const BIGNUM *B, const BIGNUM *C)
{
    BIGNUM* inv = BN_new();
    BIGNUM* one = BN_new();
    BN_set_word(one, 1);

    /* TODO evaluate whether negative numbers are OK,
     * and remove the following restriction if so. */
    if ( BN_cmp(B, zero) < 0 || BN_cmp(C, zero) == 0 ) {
        goto end;
    }
    if ( BN_mod_inverse(inv, B, C, ctx) == NULL ) {
        goto end;
    }
    if ( BN_mul(inv, inv, B, ctx) != 1 ) {
        goto end;
    }
    if ( BN_mod(inv, inv, C, ctx) != 1 ) {
        goto end;
    }
    if ( BN_cmp(C, one) != 0) {
        if ( BN_cmp(inv, one) != 0 ) {
            abort();
        }
    }
end:
    BN_free(inv);
    BN_free(one);
}

static int operation_ADD(BIGNUM* A, const BIGNUM* B, const BIGNUM* C, const BIGNUM* D, const uint8_t opt)
{
    return BN_add(A, B, C) != 1 ? -1 : 0;
}

static int operation_SUB(BIGNUM* A, const BIGNUM* B, const BIGNUM* C, const BIGNUM* D, const uint8_t opt)
{
    return BN_sub(A, B, C) != 1 ? -1 : 0;
}

static int operation_MUL(BIGNUM* A, const BIGNUM* B, const BIGNUM* C, const BIGNUM* D, const uint8_t opt)
{
    return BN_mul(A, B, C, ctx) != 1 ? -1 : 0;
}

static int operation_DIV(BIGNUM* A, const BIGNUM* B, const BIGNUM* C, const BIGNUM* D, const uint8_t opt)
{
    int ret = -1;

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

    return ret;
}

static int operation_MOD(BIGNUM* A, const BIGNUM* B, const BIGNUM* C, const BIGNUM* D, const uint8_t opt)
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

static int operation_EXP_MOD(BIGNUM* A, const BIGNUM* B, const BIGNUM* C, const BIGNUM* D, const uint8_t opt)
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

static int operation_LSHIFT(BIGNUM* A, const BIGNUM* B, const BIGNUM* C, const BIGNUM* D, const uint8_t opt)
{
    return BN_lshift(A, B, 1) != 1 ? -1 : 0;
}

static int operation_RSHIFT(BIGNUM* A, const BIGNUM* B, const BIGNUM* C, const BIGNUM* D, const uint8_t opt)
{
    return BN_rshift(A, B, 1) != 1 ? -1 : 0;
}

static int operation_GCD(BIGNUM* A, const BIGNUM* B, const BIGNUM* C, const BIGNUM* D, const uint8_t opt)
{
    return BN_gcd(A, B, C, ctx) != 1 ? -1 : 0;
}

static int operation_MOD_ADD(BIGNUM* A, const BIGNUM* B, const BIGNUM* C, const BIGNUM* D, const uint8_t opt)
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

static int operation_EXP(BIGNUM* A, const BIGNUM* B, const BIGNUM* C, const BIGNUM* D, const uint8_t opt)
{
    int ret = -1;

    if ( BN_cmp(B, zero) > 0 && BN_ucmp(B, thousand) <= 0 && BN_cmp(C, zero) > 0 && BN_ucmp(C, thousand) <= 0 ) {
        ret = BN_exp(A, B, C, ctx) != 1 ? -1 : 0;
    } else {
        ret = -1;
    }

    return ret;
}

static int operation_CMP(BIGNUM* A, const BIGNUM* B, const BIGNUM* C, const BIGNUM* D, const uint8_t opt)
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

static int operation_SQR(BIGNUM* A, const BIGNUM* B, const BIGNUM* C, const BIGNUM* D, const uint8_t opt)
{
    return BN_sqr(A, B, ctx) != 1 ? -1 : 0;
}

static int operation_NEG(BIGNUM* A, const BIGNUM* B, const BIGNUM* C, const BIGNUM* D, const uint8_t opt)
{
    return BN_sub(A, zero, B) != 1 ? -1 : 0;
}

static int operation_ABS(BIGNUM* A, const BIGNUM* B, const BIGNUM* C, const BIGNUM* D, const uint8_t opt)
{
    int ret = -1;

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

    return ret;
}

static int operation_IS_PRIME(BIGNUM* A, const BIGNUM* B, const BIGNUM* C, const BIGNUM* D, const uint8_t opt)
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

static int operation_MOD_SUB(BIGNUM* A, const BIGNUM* B, const BIGNUM* C, const BIGNUM* D, const uint8_t opt)
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

static int operation_SWAP(BIGNUM* A, BIGNUM* B, const BIGNUM* C, const BIGNUM* D, const uint8_t opt)
{
    BN_swap(A, B);
    return 0;
}

static int operation_MOD_MUL(BIGNUM* A, const BIGNUM* B, const BIGNUM* C, const BIGNUM* D, const uint8_t opt)
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

static int operation_SET_BIT(BIGNUM* A, const BIGNUM* B, const BIGNUM* C, const BIGNUM* D, const uint8_t opt)
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

static int operation_NOP(BIGNUM* A, const BIGNUM* B, const BIGNUM* C, const BIGNUM* D, const uint8_t opt)
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
        default:
            break;
    }

    return 0;
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

    test_bignum_sanity(A);
    test_bignum_sanity(B);
    test_bignum_sanity(C);
    test_bignum_sanity(D);

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
            ret = operation_ADD(A, B, C, D, opt);
            break;
        case    BN_FUZZ_OP_SUB:
            ret = operation_SUB(A, B, C, D, opt);
            break;
        case    BN_FUZZ_OP_MUL:
            ret = operation_MUL(A, B, C, D, opt);
            break;
        case    BN_FUZZ_OP_DIV:
            ret = operation_DIV(A, B, C, D, opt);
            break;
        case    BN_FUZZ_OP_MOD:
            ret = operation_MOD(A, B, C, D, opt);
            break;
        case    BN_FUZZ_OP_EXP_MOD:
            ret = operation_EXP_MOD(A, B, C, D, opt);
            break;
        case    BN_FUZZ_OP_LSHIFT:
            ret = operation_LSHIFT(A, B, C, D, opt);
            break;
        case    BN_FUZZ_OP_RSHIFT:
            ret = operation_RSHIFT(A, B, C, D, opt);
            break;
        case    BN_FUZZ_OP_GCD:
            ret = operation_GCD(A, B, C, D, opt);
            break;
        case    BN_FUZZ_OP_MOD_ADD:
            ret = operation_MOD_ADD(A, B, C, D, opt);
            break;
        case    BN_FUZZ_OP_EXP:
            ret = operation_EXP(A, B, C, D, opt);
            break;
        case    BN_FUZZ_OP_CMP:
            ret = operation_CMP(A, B, C, D, opt);
            break;
        case    BN_FUZZ_OP_SQR:
            ret = operation_SQR(A, B, C, D, opt);
            break;
        case    BN_FUZZ_OP_NEG:
            ret = operation_NEG(A, B, C, D, opt);
            break;
        case    BN_FUZZ_OP_ABS:
            ret = operation_ABS(A, B, C, D, opt);
            break;
        case    BN_FUZZ_OP_IS_PRIME:
            ret = operation_IS_PRIME(A, B, C, D, opt);
            break;
        case BN_FUZZ_OP_MOD_SUB:
            ret = operation_MOD_SUB(A, B, C, D, opt);
            break;
        case BN_FUZZ_OP_SWAP:
            ret = operation_SWAP(A, B, C, D, opt);
            break;
        case BN_FUZZ_OP_MOD_MUL:
            ret = operation_MOD_MUL(A, B, C, D, opt);
            break;
        case BN_FUZZ_OP_SET_BIT:
            ret = operation_SET_BIT(A, B, C, D, opt);
            break;
        case BN_FUZZ_OP_NOP:
            ret = operation_NOP(A, B, C, D, opt);
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
