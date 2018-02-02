#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <bnfuzz/module.h>
#include <bnfuzz/operation.h>
#include <bnfuzz/bignum.h>
#include "lib.h"

static int numbers[NUM_BIGNUMS];

static int g_number_index;

static int initialize(void)
{
    int i;
    for (i = 0; i < NUM_BIGNUMS; i++) {
        numbers[i] = i;
    }
    g_number_index = 0;
    go_bignum_initialize();
    return 0;
}

static int bignum_from_string(const char* input, void** output)
{
    GoString msg = {input, strlen(input)};
    if ( go_bignum_bignum_from_string(msg, g_number_index) == -1 ) {
        return -1;
    }
    *output = (void*)&(numbers[g_number_index]);
    g_number_index++;
    return 0;
}

static int string_from_bignum(void* input, char** output)
{
    *output = go_bignum_string_from_bignum((GoInt)*(int*)input);
    return 0;
}

static void destroy_bignum(void* bignum)
{
    g_number_index = 0;
}

static int operation(
        bignum_cluster_t* bignum_cluster,
        operation_t operation,
        uint8_t opt)
{
    GoInt A, B, C, D;
    A = *(int*)bignum_cluster->BN[0],
    B = *(int*)bignum_cluster->BN[1];
    C = *(int*)bignum_cluster->BN[2];
    D = *(int*)bignum_cluster->BN[3];
    return (int)go_bignum_operation((GoInt)operation, A, B, C, D, opt);
}

static void shutdown(void) {
    go_bignum_shutdown();
}

module_t mod_evm_geth = {
    .initialize = initialize,
    .bignum_from_string = bignum_from_string,
    .string_from_bignum = string_from_bignum,
    .destroy_bignum = destroy_bignum,
    .operation = operation,
    .shutdown = shutdown,
    .name = "EVM Geth"
};
