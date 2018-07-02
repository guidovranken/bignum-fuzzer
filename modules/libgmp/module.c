#include <stdlib.h>
#include <bnfuzz/module.h>
#include <bnfuzz/operation.h>
#include <bnfuzz/bignum.h>
#include <gmp.h>

#define MPZ_ALLOC(name) \
        name = malloc(sizeof(mpz_t));

#define MPZ_NEW(name) \
        MPZ_ALLOC(name); \
        mpz_init(*name);

#define MPZ_DECL(name) \
        mpz_t* name; \
        MPZ_NEW(name);

#define MPZ_DELETE(name) \
        mpz_clear(*name); \
        free(name); \
        name = NULL;

mpz_t* g_two = NULL;

static int initialize(void)
{
    MPZ_NEW(g_two);
    mpz_set_ui(*g_two, 2);

    return 0;
}

static int bignum_from_string(const char* input, void** output)
{
    MPZ_DECL(mpz);

    mpz_set_str(*mpz, input, 10);

    *((mpz_t**)output) = mpz;

    return 0;
}

static int string_from_bignum(void* input, char** output)
{
    mpz_t* mpz = (mpz_t*)input;

    *output = mpz_get_str(NULL, 10, *mpz);

    return 0;
}

static void destroy_bignum(void* bignum)
{
    mpz_t* mpz = (mpz_t*)bignum;

    if ( mpz == NULL ) {
        return;
    }

    MPZ_DELETE(mpz);
}

static int is_odd(mpz_t* mpz)
{
    int ret;
    mpz_t tmp;
    mpz_init(tmp);
    mpz_mod(tmp, *mpz, *g_two);
    ret = mpz_cmp_ui(tmp, 0) == 0 ? 0 : 1;
    mpz_clear(tmp);

    return ret;
}

static int operation(
        bignum_cluster_t* bignum_cluster,
        operation_t operation,
        uint8_t opt)
{
    int ret = -1;
    uint32_t status = 0;
    mpz_t *A, *B, *C, *D;

    A = (mpz_t*)bignum_cluster->BN[0];
    B = (mpz_t*)bignum_cluster->BN[1];
    C = (mpz_t*)bignum_cluster->BN[2];
    D = (mpz_t*)bignum_cluster->BN[3];

    switch ( operation ) {
        case    BN_FUZZ_OP_ADD:
            mpz_add(*A, *B, *C);
            ret = 0;
            break;
        case    BN_FUZZ_OP_SUB:
            mpz_sub(*A, *B, *C);
            ret = 0;
            break;
        case    BN_FUZZ_OP_MUL:
            mpz_mul(*A, *B, *C);
            ret = 0;
            break;
        case    BN_FUZZ_OP_DIV:
            if ( mpz_cmp_ui(*C, 0) != 0 ) {
                 mpz_div(*A, *B, *C);
                 ret = 0;
            }
            break;
        case    BN_FUZZ_OP_MOD:
            if ( mpz_cmp_ui(*B, 0) >= 0 && mpz_cmp_ui(*C, 0) > 0 ) {
                mpz_mod(*A, *B, *C);
                ret = 0;
            }
            break;
        case    BN_FUZZ_OP_EXP_MOD:
            if ( mpz_cmp_ui(*B, 0) > 0 && mpz_cmp_ui(*C, 0) > 0 ) {
                if ( opt & 1 && mpz_cmp_ui(*D, 0) > 0 && is_odd(D) ) {
                    mpz_powm_sec(*A, *B, *C, *D);
                    ret = 0;
                } else if ( mpz_cmp_ui(*D, 0) != 0 ) {
                    mpz_powm(*A, *B, *C, *D);
                    ret = 0;
                }
            }
            break;
        case    BN_FUZZ_OP_LSHIFT:
            /* TODO */
            break;
        case    BN_FUZZ_OP_RSHIFT:
            if ( mpz_cmp_ui(*B, 0) >= 0 ) {
                mpz_tdiv_q_2exp(*A, *B, 1);
                ret = 0;
            }
            break;
        case    BN_FUZZ_OP_GCD:
            mpz_gcd(*A, *B, *C);
            ret = 0;
            break;
        case    BN_FUZZ_OP_MOD_ADD:
            if ( mpz_cmp_ui(*D, 0) != 0 ) {
                mpz_add(*A, *B, *C);
                mpz_mod(*A, *A, *D);
                ret = 0;
            }
            break;
        case    BN_FUZZ_OP_CMP:
            {
                int cmpres = mpz_cmp(*B, *C);
                if ( cmpres < 0 ) {
                    mpz_set_si(*A, -1);
                } else if ( cmpres > 0 ) {
                    mpz_set_ui(*A, 1);
                } else {
                    mpz_set_ui(*A, 0);
                }
            }

            ret = 0;
            break;
        case    BN_FUZZ_OP_SQR:
            mpz_pow_ui(*A, *B, 2);
            ret = 0;
            break;
        case    BN_FUZZ_OP_NEG:
            mpz_neg(*A, *B);
            ret = 0;
            break;
        case    BN_FUZZ_OP_ABS:
            mpz_abs(*A, *B);
            ret = 0;
            break;
        case    BN_FUZZ_OP_MOD_SUB:
            if ( mpz_cmp_ui(*D, 0) != 0 ) {
                mpz_sub(*A, *B, *C);
                mpz_mod(*A, *A, *D);
                ret = 0;
            }
            break;
        case    BN_FUZZ_OP_SWAP:
            mpz_swap(*A, *B);
            ret = 0;
            break;
        case    BN_FUZZ_OP_MOD_MUL:
            if ( mpz_cmp_ui(*D, 0) != 0 ) {
                mpz_mul(*A, *B, *C);
                mpz_mod(*A, *A, *D);
                ret = 0;
            }
            break;
        default:
            ret = -1;
            break;
    }

    return ret;
}

static void shutdown(void) {
    MPZ_DELETE(g_two);
}

module_t mod_libgmp = {
    .initialize = initialize,
    .bignum_from_string = bignum_from_string,
    .string_from_bignum = string_from_bignum,
    .destroy_bignum = destroy_bignum,
    .operation = operation,
    .shutdown = shutdown,
    .name = "libgmp"
};
