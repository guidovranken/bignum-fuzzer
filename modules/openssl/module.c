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
BIGNUM *zero = NULL, *minone = NULL, *ten = NULL, *thousand = NULL;

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

    switch ( operation ) {
        case    BN_FUZZ_OP_ADD:
            ret = BN_add(A, B, C) == 0 ? -1 : 0;
            break;
        case    BN_FUZZ_OP_SUB:
            ret = BN_sub(A, B, C) == 0 ? -1 : 0;
            break;
        case    BN_FUZZ_OP_MUL:
            ret = BN_mul(A, B, C, ctx) == 0 ? -1 : 0;
            break;
        case    BN_FUZZ_OP_DIV:
            if ( BN_cmp(C, zero) != 0 ) {
                BIGNUM* rem = BN_new();
                ret = BN_div(A, rem, B, C, ctx) == 0 ? -1 : 0;
                if ( ret == 0 ) {
                    ret = BN_cmp(rem, zero) == 0 ? 0 : -1;
                }
                BN_free(rem);
            } else {
                ret = -1;
            }
            break;
        case    BN_FUZZ_OP_MOD:
            ret = BN_mod(A, B, C, ctx) == 0 ? -1 : 0;
            break;
        case    BN_FUZZ_OP_EXP_MOD:
            if ( BN_cmp(B, zero) > 0 && BN_cmp(C, zero) != 0 ) {
                if ( f_constant_time ) {
                    ret = BN_mod_exp_mont_consttime(A, B, C, D, ctx, NULL) == 0 ? -1 : 0;
                } else {
                    ret = BN_mod_exp_mont(A, B, C, D, ctx, NULL) == 0 ? -1 : 0;
                }
            } else
                ret = -1;
            break;
        case    BN_FUZZ_OP_LSHIFT:
            ret = BN_lshift(A, B, 1) == 0 ? -1 : 0;
            break;
        case    BN_FUZZ_OP_RSHIFT:
            ret = BN_rshift(A, B, 1) == 0 ? -1 : 0;
            break;
        case    BN_FUZZ_OP_GCD:
            ret = BN_gcd(A, B, C, ctx) == 0 ? -1 : 0;
            break;
        case    BN_FUZZ_OP_MOD_ADD:
            ret = BN_mod_add(A, B, C, D, ctx) == 0 ? -1 : 0;
            break;
        case    BN_FUZZ_OP_EXP:
            if ( BN_cmp(B, zero) > 0 && BN_ucmp(B, thousand) <= 0 && BN_cmp(C, zero) > 0 && BN_ucmp(C, thousand) <= 0 ) {
                ret = BN_exp(A, B, C, ctx) == 0 ? -1 : 0;
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
            ret = BN_sqr(A, B, ctx) == 0 ? -1 : 0;
            break;
        case    BN_FUZZ_OP_NEG:
            ret = BN_sub(A, zero, B) == 0 ? -1 : 0;
            break;
        case    BN_FUZZ_OP_ABS:
            if ( BN_cmp(B, zero) < 0 ) {
                if ( opt & 2 ) {
                    ret = BN_sub(A, zero, B) == 0 ? -1 : 0;
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
            }
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
