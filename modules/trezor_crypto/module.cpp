#include <stdlib.h>
#include <string.h>
#include <bnfuzz/module.h>
#include <bnfuzz/operation.h>
#include <bnfuzz/bignum.h>
#include <boost/multiprecision/cpp_int.hpp>
extern "C" {
#include "src/bignum.h"
}

using namespace std;
using namespace boost::multiprecision;

static int initialize(void)
{
    return 0;
}

static int bignum_from_string(const char* input, void** output)
{
    if ( *input == '-' ) {
        /* No negatives */
        return -1;
    }

    /* Skip leading zeroes */
    while (*input == '0') input++;


    bignum256* bn;
    try {
        uint256_t i = uint256_t(input);
        //if ( i > 256 ) return -1;
        uint8_t bndata[32] = {};
        size_t bndata_idx = 0;

        while ( i ) {
            if ( bndata_idx >= 32 ) { abort(); }
            bndata[bndata_idx++] = uint8_t(boost::uint8_t(i & 0xFF));
            i >>= 8;
        }
        bn = new bignum256;
        bn_read_le(bndata, bn);
    } catch ( std::overflow_error ) {
        return -1;
    }

    *output = bn;
    return 0;
}

static int string_from_bignum(void* input, char** output)
{
    bignum256* bn = (bignum256*)input;
    char buf[1024] = {};
    bn_format(bn, NULL, NULL, 0, 0, false, buf, sizeof(buf));
    *output = (char*)malloc(strlen(buf) + 1);
    memcpy(*output, buf, strlen(buf) + 1);
    return 0;

}

static void destroy_bignum(void* bignum)
{
    delete (bignum256*)bignum;
}

static int operation(
        bignum_cluster_t* bignum_cluster,
        operation_t operation,
        uint8_t opt)
{
    int ret;
    bignum256 *A, *B, *C, *D;

    A = (bignum256*)bignum_cluster->BN[0];
    B = (bignum256*)bignum_cluster->BN[1];
    C = (bignum256*)bignum_cluster->BN[2];
    D = (bignum256*)bignum_cluster->BN[3];

    ret = 0;
    switch ( operation ) {
        case    BN_FUZZ_OP_ADD:
            {
                bignum256 tmp = *B;
                bn_add(&tmp, C);
                *A = tmp; 
            }
            break;
        case    BN_FUZZ_OP_SUB:
            {
                bignum256 tmp = {};
                bn_subtract(B, C, &tmp);
                *A = tmp; 
            }
        case    BN_FUZZ_OP_MUL:
            {
                ret = -1;
            }
            break;
        case    BN_FUZZ_OP_LSHIFT:
            {
                bignum256 tmp = *B;
                bn_lshift(&tmp);
                *A = tmp; 
            }
            break;
        case    BN_FUZZ_OP_RSHIFT:
            {
                bignum256 tmp = *B;
                bn_rshift(&tmp);
                *A = tmp; 
            }
            break;
        case    BN_FUZZ_OP_XOR:
            {
                bn_xor(A, B, C);
            }
            break;
        default:
            ret = -1;
    }

    if ( ret == 0 && bn_bitcount(A) > 256 ) {
        ret = -1;
    }

    return ret;
}

static void shutdown(void) {}

module_t mod_trezor_crypto = {
    .initialize = initialize,
    .bignum_from_string = bignum_from_string,
    .string_from_bignum = string_from_bignum,
    .destroy_bignum = destroy_bignum,
    .operation = operation,
    .shutdown = shutdown,
    .name = "trezor-crypto"
};
