#include <stdlib.h>
#include <bnfuzz/module.h>
#include <bnfuzz/operation.h>
#include <bnfuzz/bignum.h>
#include <mpdecimal.h>

mpd_context_t g_ctx;
mpd_t* g_zero = NULL;
mpd_t* g_one = NULL;

static int initialize(void)
{
    static int inited = 0;
    if ( inited == 0 ) {
        mpd_init(&g_ctx, 100000);
        inited = 1;
    }
    g_zero = mpd_new(&g_ctx);
    mpd_sset_ssize(g_zero, 0, &g_ctx);

    g_one = mpd_new(&g_ctx);
    mpd_sset_ssize(g_one, 1, &g_ctx);
    return 0;
}

static int bignum_from_string(const char* input, void** output)
{
    mpd_t* mpd = mpd_new(&g_ctx);

    mpd_set_string(mpd, input, &g_ctx);

    *((mpd_t**)output) = mpd;

    return 0;
}

static int string_from_bignum(void* input, char** output)
{
    mpd_t* mpd = (mpd_t*)input;
    uint32_t status = 0;

    *output = mpd_qformat(mpd, "f", &g_ctx, &status);
    if ( status != 0 ) {
        *output = NULL;
        return -1;
    }

    return 0;
}

static void destroy_bignum(void* bignum)
{
    mpd_t* mpd = (mpd_t*)bignum;

    if ( mpd == NULL ) {
        return;
    }

    mpd_del(mpd);
}

static int compare(mpd_t* A, mpd_t *B)
{
    int ret;
    uint32_t status = 0;
    mpd_t* res = mpd_new(&g_ctx);
    ret = mpd_compare(res, A, B, &g_ctx);
    mpd_del(res);
    return ret;
}

void swap(mpd_t* A, mpd_t* B)
{
    mpd_t* tmp = mpd_new(&g_ctx);
    mpd_copy(tmp, A, &g_ctx);
    mpd_copy(A, B, &g_ctx);
    mpd_copy(B, tmp, &g_ctx);
    mpd_del(tmp);
}

/* Performs A = (A + abs(D)) % abs(D) */
static int special_mod(mpd_t *A, mpd_t *B, mpd_t *D)
{
    uint32_t status = 0;
    int ret;
    mpd_t* D_abs = mpd_new(&g_ctx);

    /* D = abs(D) */
    mpd_qabs(D_abs, D, &g_ctx, &status);
    ret = status == 0 ? 0 : -1;
    if ( ret != 0 ) {
        goto end;
    }

    /* A = A % D */
    mpd_qpowmod(A, A, g_one, D_abs, &g_ctx, &status);
    ret = status == 0 ? 0 : -1;
    if ( ret != 0 ) {
        goto end;
    }

    /* A = A + D */
    mpd_qadd(A, A, D_abs, &g_ctx, &status);
    ret = status == 0 ? 0 : -1;
    if ( ret != 0 ) {
        goto end;
    }

    /* A = A + D */
    mpd_qpowmod(A, A, g_one, D_abs, &g_ctx, &status);
    ret = status == 0 ? 0 : -1;
end:
    mpd_del(D_abs);
    return ret;
}

static int operation(
        bignum_cluster_t* bignum_cluster,
        operation_t operation,
        uint8_t opt)
{
    int ret = -1;
    uint32_t status = 0;
    mpd_t *A, *B, *C, *D;

    A = (mpd_t*)bignum_cluster->BN[0];
    B = (mpd_t*)bignum_cluster->BN[1];
    C = (mpd_t*)bignum_cluster->BN[2];
    D = (mpd_t*)bignum_cluster->BN[3];

    switch ( operation ) {
        case    BN_FUZZ_OP_ADD:
            mpd_qadd(A, B, C, &g_ctx, &status);
            ret = status == 0 ? 0 : -1;
            break;
        case    BN_FUZZ_OP_SUB:
            mpd_qsub(A, B, C, &g_ctx, &status);
            ret = status == 0 ? 0 : -1;
            break;
        case    BN_FUZZ_OP_MUL:
            mpd_qmul(A, B, C, &g_ctx, &status);
            ret = status == 0 ? 0 : -1;
            break;
        case    BN_FUZZ_OP_DIV:
            mpd_qdiv(A, B, C, &g_ctx, &status);
            ret = status == 0 ? 0 : -1;
            break;
        case    BN_FUZZ_OP_MOD:
            {
                mpd_t* exp = mpd_new(&g_ctx);
                mpd_qsset_ssize(exp, 1, &g_ctx, &status);
                ret = status == 0 ? 0 : -1;

                if ( ret == 0 ) {
                    mpd_qpowmod(A, B, exp, C, &g_ctx, &status);
                    ret = status == 0 ? 0 : -1;
                }

                mpd_del(exp);
            }
            break;
        case    BN_FUZZ_OP_EXP_MOD:
            if ( compare(B, g_zero) != 0 && compare(C, g_zero) != 0 )
            {
                mpd_t* D_abs = mpd_new(&g_ctx);
                mpd_qabs(D_abs, D, &g_ctx, &status);
                ret = status == 0 ? 0 : -1;
                if ( ret == 0 ) {
                    mpd_qpowmod(A, B, C, D_abs, &g_ctx, &status);
                    ret = status == 0 ? 0 : -1;
                    if ( ret == 0 ) {
                        ret = special_mod(A, B, D);
                    }
                }
                mpd_del(D_abs);
            }
            break;
        case    BN_FUZZ_OP_LSHIFT:
            /* TODO */
            break;
        case    BN_FUZZ_OP_RSHIFT:
            /* TODO */
            break;
        case    BN_FUZZ_OP_GCD:
            /* not supported */
            break;
        case    BN_FUZZ_OP_MOD_ADD:
            mpd_qadd(A, B, C, &g_ctx, &status);
            ret = status == 0 ? 0 : -1;
            if ( ret == 0 ) {
                ret = special_mod(A, B, D);
            }
            break;
        case BN_FUZZ_OP_CMP:
            mpd_qcompare(A, B, C, &g_ctx, &status);
            ret = status == 0 ? 0 : -1;
            break;
        case    BN_FUZZ_OP_SQR:
            {
                mpd_t* exp = mpd_new(&g_ctx);
                mpd_qsset_ssize(exp, 2, &g_ctx, &status);
                ret = status == 0 ? 0 : -1;
                if ( ret == 0 ) {
                    mpd_qpow(A, B, exp, &g_ctx, &status);
                    ret = status == 0 ? 0 : -1;
                }
                mpd_del(exp);
            }
            break;
        case    BN_FUZZ_OP_NEG:
            mpd_qminus(A, B, &g_ctx, &status);
            ret = status == 0 ? 0 : -1;
            break;
        case    BN_FUZZ_OP_ABS:
            mpd_qabs(A, B, &g_ctx, &status);
            ret = status == 0 ? 0 : -1;
            break;
        case    BN_FUZZ_OP_MOD_SUB:
            mpd_qsub(A, B, C, &g_ctx, &status);
            ret = status == 0 ? 0 : -1;
            if ( ret == 0 ) {
                ret = special_mod(A, B, D);
            }
            break;
        case    BN_FUZZ_OP_SWAP:
            swap(A, B);
            ret = 0;
            break;
        case    BN_FUZZ_OP_MOD_MUL:
            mpd_qmul(A, B, C, &g_ctx, &status);
            ret = status == 0 ? 0 : -1;
            if ( ret == 0 ) {
                ret = special_mod(A, B, D);
            }
            break;
        default:
            ret = -1;
            break;
    }

    return ret;
}

static void shutdown(void) {
    mpd_del(g_zero);
    mpd_del(g_one);
}

module_t mod_libmpdec = {
    .initialize = initialize,
    .bignum_from_string = bignum_from_string,
    .string_from_bignum = string_from_bignum,
    .destroy_bignum = destroy_bignum,
    .operation = operation,
    .shutdown = shutdown,
    .name = "libmpdec"
};
