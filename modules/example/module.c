#include <stdlib.h>
#include <string.h>
#include <bnfuzz/module.h>
#include <bnfuzz/operation.h>
#include <bnfuzz/bignum.h>

static int initialize(void)
{
    /* TODO: write your module initialization code here */
    return 0;
}

static int bignum_from_string(const char* input, void** output)
{
    /* TODO:
     * Convert 'input' to a pointer to your internal bignum object.
     * Store this pointer in *output.
     *
     * 'input' is a human-readable base 10 representation of a number as a
     * null-terminated string.
     *
     * Return 0 for success, return -1 for failure.
     */

    if ( 0 /* if error */ ) {
        goto error;
    }
    return 0;

error:
    return -1;
}

static int string_from_bignum(void* input, char** output)
{
    /* TODO
     * Convert your internal bignum object (pointed to by 'input')
     * to a human-readable base 10 representation of the number as a
     * null-terminated string.
     *
     * You are responsible for allocating *output, always with malloc().
     *
     * Return 0 for success, return -1 for failure.
     */

    if ( 0 /* if error */ ) {
        goto error;
    }

    return 0;
error:
    return -1;
}

static void destroy_bignum(void* bignum)
{
    /* TODO: destroy your internal bignum object */
}

static int operation(
        bignum_cluster_t* bignum_cluster,
        operation_t operation,
        uint8_t opt)
{
    /* TODO
     * Pointers to your internal bignum objects are here:
     *
     * (BIGNUM*)bignum_cluster->BN[0];
     * (BIGNUM*)bignum_cluster->BN[1];
     * (BIGNUM*)bignum_cluster->BN[2];
     * (BIGNUM*)bignum_cluster->BN[3];
     *
     * Handle as many operations declared in the 'operation' enum in
     * include/bnfuzz/operation.h
     *
     * If you don't support a certain operation, always return -1.
     *
     * Always store the result of the operation in the first bignum
     * ((BIGNUM*)bignum_cluster->BN[0]) and don't alter the others.
     *
     * You can either ignore the 'opt' variable, or use it to internally choose
     * from several implementations that perform the same operation, eg.:
     * if ( operation == BN_FUZZ_OP_ADD )
     *     if ( opt & 1 ) 
     *         A = B + C
     *     else
     *         A = 0 - (-B + -C)
     *
     * Return 0 for success, return -1 for failure.
    */

    return 0; /* Or return -1 in case of failure */
}

static void shutdown(void)
{
    /* TODO: write your module destruction code here */
}

module_t mod_openssl = {
    .initialize = initialize,
    .bignum_from_string = bignum_from_string,
    .string_from_bignum = string_from_bignum,
    .destroy_bignum = destroy_bignum,
    .operation = operation,
    .shutdown = shutdown,
    .name = "EXAMPLE" /* TODO: change this */
};
