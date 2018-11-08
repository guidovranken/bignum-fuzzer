#include <stdlib.h>
#include <string.h>
#include <bnfuzz/module.h>
#include <bnfuzz/operation.h>
#include <bnfuzz/bignum.h>
#include <boost/multiprecision/cpp_int.hpp>
#include <iostream>
#include <sstream>

using namespace std;
using namespace boost::multiprecision;

static int initialize(void)
{
    return 0;
}

static int bignum_from_string(const char* input, void** output)
{
    uint256_t* i = NULL;
    bool negative = false;
    if ( *input == '-' ) {
        negative = true;
        input++;
    }

    /* Skip leading zeroes */
    while (*input == '0') input++;

    try {
        i = new uint256_t(input);
    } catch ( std::overflow_error ) {
        return -1;
    }

    if ( negative ) {
        subtract(*i, uint256_t(0), *i);
    }

    *output = i;
    return 0;
}

static int string_from_bignum(void* input, char** output)
{
    std::stringstream sstream;
    sstream << *(uint256_t*)input;
    string s = sstream.str();
    *output = (char*)malloc(strlen(s.c_str())+1);
    memcpy(*output, s.c_str(), strlen(s.c_str())+1);
    return 0;
}

static void destroy_bignum(void* bignum)
{
    delete (uint256_t*)bignum;
}

static int operation(
        bignum_cluster_t* bignum_cluster,
        operation_t operation,
        uint8_t opt)
{
    int ret;
    uint256_t *A, *B, *C, *D;

    A = (uint256_t*)bignum_cluster->BN[0];
    B = (uint256_t*)bignum_cluster->BN[1];
    C = (uint256_t*)bignum_cluster->BN[2];
    D = (uint256_t*)bignum_cluster->BN[3];

    ret = 0;
    try {
        switch ( operation ) {
            case    BN_FUZZ_OP_ADD:
                add(*A, *B, *C);
                break;
            case    BN_FUZZ_OP_SUB:
                subtract(*A, *B, *C);
                break;
            case    BN_FUZZ_OP_MUL:
                multiply(*A, *B, *C);
                break;
            case    BN_FUZZ_OP_DIV:
                {
                    if ( *C != uint256_t(0) ) {
                        uint256_t rem(0);
                        divide_qr(*B, *C, *A, rem);
                        if ( rem != 0 ) {
                            ret = -1;
                        }
                    } else {
                        ret = -1;
                    }
                }
                break;
            case    BN_FUZZ_OP_MOD:
                if ( *C != uint256_t(0) ) {
                    *A = powm(*B, uint256_t(1), *C);
                } else {
                    ret = -1;
                }
                break;
            case    BN_FUZZ_OP_EXP_MOD:
                {
                    if ( *B >= uint256_t(0) && *C >= uint256_t(0) && *D != uint256_t(0) ) {
                        *A = powm(*B, *C, *D);
                    } else {
                        ret = -1;
                    }
                }
                break;
            case    BN_FUZZ_OP_LSHIFT:
                *A = *B << 1;
                break;
            case    BN_FUZZ_OP_RSHIFT:
                *A = *B >> 1;
                break;
            case    BN_FUZZ_OP_GCD:
                *A = gcd(*B, *C);
                break;
            case    BN_FUZZ_OP_MOD_ADD:
                /*
                if ( *D > uint256_t(0) ) {
                    add(*A, *B, *C);
                    *A = powm(*A, uint256_t(1), *D);
                    add(*A, *A, *D);
                    *A = powm(*A, uint256_t(1), *D);
                } else {
                    ret = -1;
                }
                */
                ret = -1;
                break;
            case    BN_FUZZ_OP_EXP:
                if ( *B > uint256_t(0) && *B <= uint256_t(1000) && *C > uint256_t(0) && *C <= uint256_t(1000) ) {
                    int exp = static_cast<int>(*C);
                    *A = pow(*B, exp);
                    ret = 0;
                } else {
                    ret = -1;
                }
                break;
            case    BN_FUZZ_OP_CMP:
                if ( *B > *C ) {
                    *A = 2;
                } else {
                    if ( *B < *C ) {
                        *A = 0;
                    } else {
                        *A = 1;
                    }
                }
                ret = 0;
                break;
            case    BN_FUZZ_OP_SQR:
                multiply(*A, *B, *B);
                ret = 0;
                break;
            case    BN_FUZZ_OP_NEG:
                /*
                *A = uint256_t(0) - *B;
                ret = 0;
                */
                ret = -1;
                break;
            case    BN_FUZZ_OP_ABS:
                /*
                *A = abs(*B);
                ret = 0;
                */
                ret = -1;
                break;
            case    BN_FUZZ_OP_MOD_SUB:
                if ( *D > cpp_int(0) ) {
                    subtract(*A, *B, *C);
                    *A = powm(*A, uint256_t(1), *D);
                } else {
                    ret = -1;
                }
                break;
            case    BN_FUZZ_OP_SWAP:
                {
                    uint256_t tmp = *A;
                    *A = *B;
                    *B = tmp;
                    ret = 0;
                }
                break;
            case    BN_FUZZ_OP_MOD_MUL:
                if ( *B > uint256_t(0) && *C > uint256_t(0) && *D > uint256_t(0) ) {
                    multiply(*A, *B, *C);
                    *A = powm(*A, uint256_t(1), *D);
                } else {
                    ret = -1;
                }
                break;
            default:
                ret = -1;
        }
    } catch ( std::overflow_error ) {
        return -1;
    }

    return ret;
}

static void shutdown(void) {}

module_t mod_cpp_boost_uint256 = {
    .initialize = initialize,
    .bignum_from_string = bignum_from_string,
    .string_from_bignum = string_from_bignum,
    .destroy_bignum = destroy_bignum,
    .operation = operation,
    .shutdown = shutdown,
    .name = "C++ boost::multiprecision uint256"
};
