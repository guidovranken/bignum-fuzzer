#ifndef BNFUZZ_OPERATION_H
#define BNFUZZ_OPERATION_H

#include <stdint.h>
#include <stddef.h>

enum operation
{
    BN_FUZZ_OP_ETH_ADD = 1,
    BN_FUZZ_OP_ETH_SUB = 2,
    BN_FUZZ_OP_ETH_MUL = 3,
    BN_FUZZ_OP_ETH_DIV = 4,
    BN_FUZZ_OP_ETH_SDIV = 5,
    BN_FUZZ_OP_ETH_MOD = 6,
    BN_FUZZ_OP_ETH_SMOD = 7,
    BN_FUZZ_OP_ETH_EXP = 8,
    BN_FUZZ_OP_ETH_SIGNEXTEND = 9,
    BN_FUZZ_OP_ETH_NOT = 10,
    BN_FUZZ_OP_ETH_LT = 11,
    BN_FUZZ_OP_ETH_GT = 12,
    BN_FUZZ_OP_ETH_SLT = 13,
    BN_FUZZ_OP_ETH_SGT = 14,
    BN_FUZZ_OP_ETH_EQ = 15,
    BN_FUZZ_OP_ETH_ISZERO = 16,
    BN_FUZZ_OP_ETH_AND = 17,
    BN_FUZZ_OP_ETH_OR = 18,
    BN_FUZZ_OP_ETH_XOR = 19,
    BN_FUZZ_OP_ETH_BYTE = 20,
    BN_FUZZ_OP_ETH_ADDMOD = 21,
    BN_FUZZ_OP_ETH_MULMOD = 22,
    BN_FUZZ_OP_ETH_MAX = 23,
};

typedef uint8_t operation_t;
char* operation_to_short_id_string(operation_t op);
char* operation_to_description_string(operation_t op);
char* operation_to_operator_string(operation_t op);
operation_t size_t_to_operation(size_t val);

#endif
