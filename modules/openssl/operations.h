#ifndef BIGNUM_FUZZER_OPENSSL_OPERATIONS_H
#define BIGNUM_FUZZER_OPENSSL_OPERATIONS_H
#include <openssl/bn.h>
#include <stdint.h>
int operation_ADD(BIGNUM* A, const BIGNUM* B, const BIGNUM* C, const BIGNUM* D, const uint8_t opt);
int operation_SUB(BIGNUM* A, const BIGNUM* B, const BIGNUM* C, const BIGNUM* D, const uint8_t opt);
int operation_MUL(BIGNUM* A, const BIGNUM* B, const BIGNUM* C, const BIGNUM* D, const uint8_t opt);
int operation_DIV(BIGNUM* A, const BIGNUM* B, const BIGNUM* C, const BIGNUM* D, const uint8_t opt);
int operation_MOD(BIGNUM* A, const BIGNUM* B, const BIGNUM* C, const BIGNUM* D, const uint8_t opt);
int operation_EXP_MOD(BIGNUM* A, const BIGNUM* B, const BIGNUM* C, const BIGNUM* D, const uint8_t opt);
int operation_LSHIFT(BIGNUM* A, const BIGNUM* B, const BIGNUM* C, const BIGNUM* D, const uint8_t opt);
int operation_RSHIFT(BIGNUM* A, const BIGNUM* B, const BIGNUM* C, const BIGNUM* D, const uint8_t opt);
int operation_GCD(BIGNUM* A, const BIGNUM* B, const BIGNUM* C, const BIGNUM* D, const uint8_t opt);
int operation_MOD_ADD(BIGNUM* A, const BIGNUM* B, const BIGNUM* C, const BIGNUM* D, const uint8_t opt);
int operation_EXP(BIGNUM* A, const BIGNUM* B, const BIGNUM* C, const BIGNUM* D, const uint8_t opt);
int operation_CMP(BIGNUM* A, const BIGNUM* B, const BIGNUM* C, const BIGNUM* D, const uint8_t opt);
int operation_SQR(BIGNUM* A, const BIGNUM* B, const BIGNUM* C, const BIGNUM* D, const uint8_t opt);
int operation_NEG(BIGNUM* A, const BIGNUM* B, const BIGNUM* C, const BIGNUM* D, const uint8_t opt);
int operation_ABS(BIGNUM* A, const BIGNUM* B, const BIGNUM* C, const BIGNUM* D, const uint8_t opt);
int operation_IS_PRIME(BIGNUM* A, const BIGNUM* B, const BIGNUM* C, const BIGNUM* D, const uint8_t opt);
int operation_MOD_SUB(BIGNUM* A, const BIGNUM* B, const BIGNUM* C, const BIGNUM* D, const uint8_t opt);
int operation_SWAP(BIGNUM* A, BIGNUM* B, const BIGNUM* C, const BIGNUM* D, const uint8_t opt);
int operation_MOD_MUL(BIGNUM* A, const BIGNUM* B, const BIGNUM* C, const BIGNUM* D, const uint8_t opt);
int operation_SET_BIT(BIGNUM* A, const BIGNUM* B, const BIGNUM* C, const BIGNUM* D, const uint8_t opt);
int operation_NOP(BIGNUM* A, const BIGNUM* B, const BIGNUM* C, const BIGNUM* D, const uint8_t opt);
#endif
