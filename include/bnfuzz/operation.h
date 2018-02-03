#ifndef BNFUZZ_OPERATION_H
#define BNFUZZ_OPERATION_H

#include <stdint.h>
#include <stddef.h>

enum operation
{
    BN_FUZZ_OP_ADD = 1,
    BN_FUZZ_OP_SUB = 2,
    BN_FUZZ_OP_MUL = 3,
    BN_FUZZ_OP_DIV = 4,
    BN_FUZZ_OP_MOD = 5,
    BN_FUZZ_OP_EXP_MOD = 6,
    BN_FUZZ_OP_LSHIFT = 7,
    BN_FUZZ_OP_RSHIFT = 8,
    BN_FUZZ_OP_GCD = 9,
    BN_FUZZ_OP_MOD_ADD = 10,
    BN_FUZZ_OP_EXP = 11,
    BN_FUZZ_OP_CMP = 12,
    BN_FUZZ_OP_SQR = 13,
    BN_FUZZ_OP_NEG = 14,
    BN_FUZZ_OP_ABS = 15,
    BN_FUZZ_OP_IS_PRIME = 16,
    BN_FUZZ_OP_MOD_SUB = 17,
    BN_FUZZ_OP_SWAP = 18,
    BN_FUZZ_OP_MOD_MUL = 19,
};

typedef uint8_t operation_t;
char* operation_to_short_id_string(operation_t op);
char* operation_to_description_string(operation_t op);
char* operation_to_operator_string(operation_t op);
operation_t size_t_to_operation(size_t val);

#endif
