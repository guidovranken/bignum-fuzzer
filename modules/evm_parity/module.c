#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <bnfuzz/module.h>
#include <bnfuzz/operation.h>
#include <bnfuzz/bignum.h>

void rust_bignum_initialize(void);
int rust_bignum_bignum_from_string(const char* s, int bn_index);
char* rust_bignum_string_from_bignum(int bn_index);
void rust_bignum_free_string(char* s);
int rust_bignum_operation(int op, int opt);
void rust_bignum_shutdown(void);

static int numbers[NUM_BIGNUMS];

static int g_number_index;

static int initialize(void)
{
    int i;
    for (i = 0; i < NUM_BIGNUMS; i++) {
        numbers[i] = i;
    }
    g_number_index = 0;
    rust_bignum_initialize();
    return 0;
}

static int bignum_from_string(const char* input, void** output)
{
    if ( rust_bignum_bignum_from_string(input, g_number_index) == -1 ) {
        return -1;
    }
    *output = (void*)&(numbers[g_number_index]);
    g_number_index++;
    return 0;
}

static int string_from_bignum(void* input, char** output)
{
    char* tmp = rust_bignum_string_from_bignum(*(int*)input);
    size_t len = strlen(tmp)+1;
    *output = malloc(len);
    memcpy(*output, tmp, len);
    rust_bignum_free_string(tmp);
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
    return (int)rust_bignum_operation((int)operation, (int)opt);
}

static void shutdown(void) {
    rust_bignum_shutdown();
}

module_t mod_evm_parity = {
    .initialize = initialize,
    .bignum_from_string = bignum_from_string,
    .string_from_bignum = string_from_bignum,
    .destroy_bignum = destroy_bignum,
    .operation = operation,
    .shutdown = shutdown,
    .name = "EVM Parity"
};
