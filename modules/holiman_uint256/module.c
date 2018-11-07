#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <bnfuzz/module.h>
#include <bnfuzz/operation.h>
#include <bnfuzz/bignum.h>
#include <stdbool.h>
#include "holiman_uint256.h"

static int numbers[NUM_BIGNUMS];

static int g_number_index;

static uint8_t CoverTab[65536];
extern void libFuzzerCustomMemcmp(void *caller_pc, const void *s1, const void *s2, size_t n);
typedef void (*guidance_callback_t)(size_t, size_t, bool);

guidance_callback_t guidance_callback = NULL;

void LLVMFuzzerCustomGuidance(guidance_callback_t fn)
{
    guidance_callback = fn;
}

static int inited = 0; 

static int initialize(void)
{
    int i;
    for (i = 0; i < NUM_BIGNUMS; i++) {
        numbers[i] = i;
    }
    g_number_index = 0;
    if ( inited == 0 ) {
        HolimanUint256Initialize(CoverTab, sizeof(CoverTab), (void*)libFuzzerCustomMemcmp);
        inited = 1;
    }
    return 0;
}

static int bignum_from_string(const char* input, void** output)
{
    GoString msg = {input, strlen(input)};
    const int ret = HolimanUint256BignumFromString(msg, g_number_index);
    if ( ret != 0 ) {
        return -1;
    }
    *output = (void*)&(numbers[g_number_index]);
    g_number_index++;
    return 0;
}

static int string_from_bignum(void* input, char** output)
{
    *output = HolimanUint256StringFromBignum((GoInt)*(int*)input);
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
    return (int)HolimanUint256BignumOperation((GoInt)operation, A, B, C, D, opt);
}

static void shutdown(void) {
    if ( guidance_callback != NULL ) {
        size_t coverage = 0;

        for (size_t i = 0; i < sizeof(CoverTab); i++) {
            coverage += CoverTab[i] ? 1 : 0;
        }

        guidance_callback(1, coverage, true);
    }
}

module_t mod_holiman_uint256 = {
    .initialize = initialize,
    .bignum_from_string = bignum_from_string,
    .string_from_bignum = string_from_bignum,
    .destroy_bignum = destroy_bignum,
    .operation = operation,
    .shutdown = shutdown,
    .name = "Holiman Uint256"
};
