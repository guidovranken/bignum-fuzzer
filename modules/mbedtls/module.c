#include <stdlib.h>
#include <bnfuzz/module.h>
#include <bnfuzz/operation.h>
#include <bnfuzz/bignum.h>
#include <mbedtls/bignum.h>

static int initialize(void)
{
    return 0;
}

static int bignum_from_string(const char* input, void** output)
{
    mbedtls_mpi* mpi = NULL;

    *output = NULL;

    if ( (mpi = malloc(sizeof(*mpi))) == NULL ) {
        goto error;
    }
    
    mbedtls_mpi_init(mpi);

    if ( mbedtls_mpi_read_string(mpi, 10, input) != 0 ) {
        goto error;
    }

    *((mbedtls_mpi**)output) = mpi;
    return 0;

error:
    free(mpi);
    
    return -1;
}

static int string_from_bignum(void* input, char** output)
{
    mbedtls_mpi* mpi = (mbedtls_mpi*)input;
    size_t olen;
    int ret;

    *output = NULL;

    ret = mbedtls_mpi_write_string(mpi, 10, NULL, 0, &olen);
    if ( ret != MBEDTLS_ERR_MPI_BUFFER_TOO_SMALL ) {
        goto error;
    }

    if ( (*output = malloc(olen)) == NULL ) {
        goto error;
    }

    if ( mbedtls_mpi_write_string(mpi, 10, *output, olen, &olen) != 0 ) {
        goto error;
    }

    return 0;
error:
    free(*output);
    *output = NULL;
    return -1;
}

static void destroy_bignum(void* bignum)
{
    mbedtls_mpi* mpi = (mbedtls_mpi*)bignum;

    if ( mpi  == NULL ) {
        return;
    }

    mbedtls_mpi_free(mpi);

    free(mpi);
}

/* Helper function that:
 *      - Asserts that the input bignum is within the range [-INT_MAX..INT_MAX]
 *      - Converts the bignum to a base 10 string representation
 *      - Uses strtol to convert the string representation into an integer
 *
 * If any of the above operations fail, error is set. On success, the signed integer
 * converted from the input bignum is returned.
 *
 */
static int mpi_to_int(mbedtls_mpi* mpi, int *error)
{
    char* output = NULL;
    long int l;

    if ( mbedtls_mpi_cmp_int(mpi, INT_MAX) > 0 || mbedtls_mpi_cmp_int(mpi, -INT_MAX) < 0) {
        *error = 1;
        return 0;
    }
    if ( string_from_bignum(mpi, &output) != 0 ) {
        *error = 1;
        return 0;
    }

    if ( (l = strtol(output, NULL, 10)) == LONG_MAX ) {
        *error = 1;
        free(output);
        return 0;
    }
    free(output);

    *error = 0;

    return (int)l;
}

static int operation(
        bignum_cluster_t* bignum_cluster,
        operation_t operation,
        uint8_t opt)
{
    int ret = -1;
    mbedtls_mpi *A, *B, *C, *D;

    A = (mbedtls_mpi*)bignum_cluster->BN[0];
    B = (mbedtls_mpi*)bignum_cluster->BN[1];
    C = (mbedtls_mpi*)bignum_cluster->BN[2];
    D = (mbedtls_mpi*)bignum_cluster->BN[3];

    switch ( operation ) {
        case    BN_FUZZ_OP_ADD:
            if ( opt & 1 ) {
                /* First alternative: convert bignum to signed integer,
                 * then add signed integer to bignum */
                int error, i = mpi_to_int(C, &error);
                if ( error ) {
                    ret = -1;
                } else {
                    ret = mbedtls_mpi_add_int(A, B, i) == 0 ? 0 : -1;
                }
            } else {
                /* Second alternative: add bignum directly to bignum */
                ret = mbedtls_mpi_add_mpi(A, B, C) == 0 ? 0 : -1;
            }
            break;
        case    BN_FUZZ_OP_SUB:
            if ( opt & 1 ) {
                /* First alternative: convert bignum to signed integer,
                 * then subtract signed integer from bignum */
                int error, i = mpi_to_int(C, &error);
                if ( error ) {
                    ret = -1;
                } else {
                    ret = mbedtls_mpi_sub_int(A, B, i) == 0 ? 0 : -1;
                }
            } else {
                /* Second alternative: subtract bignum directly from bignum */
                ret = mbedtls_mpi_sub_mpi(A, B, C) == 0 ? 0 : -1;
            }
            break;
        case    BN_FUZZ_OP_MUL:
            if ( opt & 1 ) {
                /* First alternative: convert bignum to signed integer,
                 * then multiply signed integer with bignum */
                int error, i = mpi_to_int(C, &error);
                if ( error ) {
                    ret = -1;
                } else {
                    if ( i >= 0 ) {
                        ret = mbedtls_mpi_mul_int(A, B, i) == 0 ? 0 : -1;
                    } else {
                        ret = -1;
                    }
                }
            } else {
                /* Second alternative: multiply bignum directly with bignum */
                ret = mbedtls_mpi_mul_mpi(A, B, C) == 0 ? 0 : -1;
            }
            break;
        case    BN_FUZZ_OP_DIV:
            {
                mbedtls_mpi tmp;
                mbedtls_mpi_init(&tmp);
                ret = mbedtls_mpi_div_mpi(A, &tmp, B, C) == 0 ? 0 : -1;
                mbedtls_mpi_free(&tmp);
            }
            break;
        case    BN_FUZZ_OP_MOD:
            if ( mbedtls_mpi_cmp_int(B, 0) > 0 ) {
                ret = mbedtls_mpi_mod_mpi(A, B, C) == 0 ? 0 : -1;
            } else {
                ret = -1;
            }
            break;
        case    BN_FUZZ_OP_EXP_MOD:
            if ( mbedtls_mpi_cmp_int(B, 0) > 0 && mbedtls_mpi_cmp_int(C, 0) != 0 ) {
                if ( opt & 1 ) {
                    mbedtls_mpi RR;
                    mbedtls_mpi_init(&RR);
                    ret = mbedtls_mpi_exp_mod(A, B, C, D, &RR) == 0 ? 0 : -1;
                    mbedtls_mpi_free(&RR);
                } else {
                    ret = mbedtls_mpi_exp_mod(A, B, C, D, NULL) == 0 ? 0 : -1;
                }
            } else {
                ret = -1;
            }
            break;
        case    BN_FUZZ_OP_LSHIFT:
            {
                mbedtls_mpi* tmp = NULL;
                if ( (tmp = malloc(sizeof(*tmp))) == NULL ) {
                    ret = -1;
                } else {
                    mbedtls_mpi_init(tmp);
                    if ( mbedtls_mpi_copy(tmp, B) != 0 ) {
                        mbedtls_mpi_free(tmp);
                        free(tmp);
                        ret = -1;
                    } else {
                        ret = mbedtls_mpi_shift_l(tmp, 1) == 0 ? 0 : -1;
                        if ( ret == 0 ) {
                            ret = mbedtls_mpi_copy(A, tmp) == 0 ? 0 : -1;
                        }
                        mbedtls_mpi_free(tmp);
                        free(tmp);
                    }
                }
            }
            break;
        case    BN_FUZZ_OP_RSHIFT:
            {
                mbedtls_mpi* tmp = NULL;
                if ( (tmp = malloc(sizeof(*tmp))) == NULL ) {
                    ret = -1;
                } else {
                    mbedtls_mpi_init(tmp);
                    if ( mbedtls_mpi_copy(tmp, B) != 0 ) {
                        mbedtls_mpi_free(tmp);
                        free(tmp);
                        ret = -1;
                    } else {
                        ret = mbedtls_mpi_shift_r(tmp, 1) == 0 ? 0 : -1;
                        if ( ret == 0 ) {
                            ret = mbedtls_mpi_copy(A, tmp) == 0 ? 0 : -1;
                        }
                        mbedtls_mpi_free(tmp);
                        free(tmp);
                    }
                }
            }
            break;
        case    BN_FUZZ_OP_GCD:
            if ( mbedtls_mpi_cmp_int(B, 0) > 0 && mbedtls_mpi_cmp_int(C, 0) > 0 ) {
                ret = mbedtls_mpi_gcd(A, B, C) == 0 ? 0 : -1;
            } else {
                ret = -1;
            }
            break;
        case    BN_FUZZ_OP_MOD_ADD:
            {
                ret = mbedtls_mpi_add_mpi(A, B, C) == 0 ? 0 : -1;

                if ( ret == 0 ) {
                    ret = mbedtls_mpi_mod_mpi(A, A, D) == 0 ? 0 : -1;
                } else {
                    ret = -1;
                }
            }
            break;
        case    BN_FUZZ_OP_EXP:
            if ( mbedtls_mpi_cmp_int(B, 0) > 0 && mbedtls_mpi_cmp_int(B, 1000) <= 0 && mbedtls_mpi_cmp_int(C, 0) > 0 && mbedtls_mpi_cmp_int(C, 1000) <= 0 ) {
                ret = -1; /* TODO */
            } else {
                ret = -1;
            }
            break;
        case BN_FUZZ_OP_CMP:
            {
                if ( opt & 1 ) {
                    /* First alternative: convert bignum to signed integer,
                     * then compare signed integer with bignum */
                    int error, i = mpi_to_int(C, &error);
                    if ( error ) {
                        ret = -1;
                    } else {
                        int c = mbedtls_mpi_cmp_int(B, i);
                        ret = mbedtls_mpi_lset(A, c) == 0 ? 0 : -1;
                    }
                } else {
                    /* Second alternative: compare bignum directly with bignum */
                    int c = mbedtls_mpi_cmp_mpi(B, C);
                    ret = mbedtls_mpi_lset(A, c) == 0 ? 0 : -1;
                }
            }
            break;
        case    BN_FUZZ_OP_SQR:
            {
                ret = mbedtls_mpi_mul_mpi(A, B, B) == 0 ? 0 : -1;
            }
            break;
        case    BN_FUZZ_OP_NEG:
            {
                /* Set A = 0 */
                ret = mbedtls_mpi_lset(A, 0) == 0 ? 0 : -1;
                if ( ret == 0 ) {
                    /* A = A - B */
                    ret = mbedtls_mpi_sub_mpi(A, A, B) == 0 ? 0 : -1;
                }
            }
            break;
        case    BN_FUZZ_OP_ABS:
            {
                ret = mbedtls_mpi_lset(A, 0) == 0 ? 0 : -1;
                if ( ret == 0 ) {
                    ret = mbedtls_mpi_add_abs(A, A, B) == 0 ? 0 : -1;
                }
            }
            break;
        case    BN_FUZZ_OP_MOD_SUB:
            {
                ret = mbedtls_mpi_sub_mpi(A, B, C) == 0 ? 0 : -1;

                if ( ret == 0 ) {
                    ret = mbedtls_mpi_mod_mpi(A, A, D) == 0 ? 0 : -1;
                } else {
                    ret = -1;
                }
            }
            break;
        case    BN_FUZZ_OP_SWAP:
            {
                mbedtls_mpi_swap(A, B);
                ret = 0;
            }
            break;
        case    BN_FUZZ_OP_MOD_MUL:
            {
                ret = mbedtls_mpi_mul_mpi(A, B, C) == 0 ? 0 : -1;

                if ( ret == 0 && mbedtls_mpi_cmp_int(A, 0) >= 0 && mbedtls_mpi_cmp_int(D, 0) > 0 ) {
                    ret = mbedtls_mpi_mod_mpi(A, A, D) == 0 ? 0 : -1;
                } else {
                    ret = -1;
                }
            }
            break;
        default:
            ret = -1;
    }

    return ret;
}

static void shutdown(void) { }

module_t mod_mbedtls = {
    .initialize = initialize,
    .bignum_from_string = bignum_from_string,
    .string_from_bignum = string_from_bignum,
    .destroy_bignum = destroy_bignum,
    .operation = operation,
    .shutdown = shutdown,
    .name = "mbed TLS"
};
