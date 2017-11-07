#ifndef BNDIFF_BIGNUM_H
#define BNDIFF_BIGNUM_H

#include <bndiff/config.h>

typedef struct {
    void*               BN[NUM_BIGNUMS];
} bignum_cluster_t;

typedef void* bignum_t;

#endif
