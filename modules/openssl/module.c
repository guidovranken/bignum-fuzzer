#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/crypto.h>
#include <bnfuzz/module.h>
#include <bnfuzz/operation.h>
#include <bnfuzz/bignum.h>
#include "operations.h"
#include "sanity.h"

BN_CTX *ctx = NULL;
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
