#ifndef BNFUZZ_BIGNUM_H
#define BNFUZZ_BIGNUM_H

#include <bnfuzz/config.h>

typedef struct {
    void*               BN[NUM_BIGNUMS];
} bignum_cluster_t;

typedef void* bignum_t;

#endif
