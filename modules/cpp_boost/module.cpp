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
    cpp_int* i = NULL;
    bool negative = false;
    if ( *input == '-' ) {
        negative = true;
        input++;
    }

    /* Skip leading zeroes */
    while (*input == '0') input++;

    i = new cpp_int(input);

    if ( negative ) {
        subtract(*i, cpp_int(0), *i);
    }

    *output = i;
    return 0;
}

static int string_from_bignum(void* input, char** output)
{
    std::stringstream sstream;
    sstream << *(cpp_int*)input;
    string s = sstream.str();
    *output = (char*)malloc(strlen(s.c_str())+1);
    memcpy(*output, s.c_str(), strlen(s.c_str())+1);
    return 0;
}
static void destroy_bignum(void* bignum)
{
    delete (cpp_int*)bignum;
}
static int operation(
        bignum_cluster_t* bignum_cluster,
        operation_t operation,
        uint8_t opt)
{
    int ret;
    cpp_int *A, *B, *C, *D;

    A = (cpp_int*)bignum_cluster->BN[0];
    B = (cpp_int*)bignum_cluster->BN[1];
    C = (cpp_int*)bignum_cluster->BN[2];
    D = (cpp_int*)bignum_cluster->BN[3];

    ret = 0;
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
                if ( *C != cpp_int(0) ) {
                    cpp_int rem(0);
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
            if ( *C != cpp_int(0) ) {
                *A = powm(*B, cpp_int(1), *C);
            } else {
                ret = -1;
            }
            break;
        case    BN_FUZZ_OP_EXP_MOD:
            {
                if ( *B >= cpp_int(0) && *C >= cpp_int(0) && *D != cpp_int(0) ) {
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
            ret = -1;
            gcd(*A, *B);
            /* XXX */
            break;
        case    BN_FUZZ_OP_MOD_ADD:
            if ( *D != cpp_int(0) ) {
                add(*A, *B, *C);
                *A = powm(*A, cpp_int(1), *D);
            } else {
                ret = -1;
            }
            break;
        case    BN_FUZZ_OP_EXP:
            if ( *B > cpp_int(0) && *B <= cpp_int(1000) && *C > cpp_int(0) && *C <= cpp_int(1000) ) {
                int exp = static_cast<int>(*C);
                *A = pow(*B, exp);
                ret = 0;
            } else {
                ret = -1;
            }
            break;
        case    BN_FUZZ_OP_CMP:
            if ( *B > *C ) {
                *A = 1;
            } else {
                if ( *B < *C ) {
                    *A = -1;
                } else {
                    *A = 0;
                }
            }
            ret = 0;
            break;
        case    BN_FUZZ_OP_SQR:
            multiply(*A, *B, *B);
            ret = 0;
            break;
        case    BN_FUZZ_OP_NEG:
            *A = cpp_int(0) - *B;
            ret = 0;
            break;
        case    BN_FUZZ_OP_ABS:
            *A = abs(*B);
            ret = 0;
            break;
        case    BN_FUZZ_OP_MOD_SUB:
            if ( *D != cpp_int(0) ) {
                subtract(*A, *B, *C);
                *A = powm(*A, cpp_int(1), *D);
            } else {
                ret = -1;
            }
            break;
        case    BN_FUZZ_OP_SWAP:
            {
                cpp_int tmp = *A;
                *A = *B;
                *B = tmp;
                ret = 0;
            }
            break;
        default:
            ret = -1;
    }

    return ret;
}

static void shutdown(void) {}

module_t mod_cpp_boost = {
    .initialize = initialize,
    .bignum_from_string = bignum_from_string,
    .string_from_bignum = string_from_bignum,
    .destroy_bignum = destroy_bignum,
    .operation = operation,
    .shutdown = shutdown,
    .name = "C++ boost::multiprecision"
};
