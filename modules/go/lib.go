package main

import "C"

import (
    "math/big"
)
const (
    BN_FUZZ_OP_ADD = 1
    BN_FUZZ_OP_SUB = 2
    BN_FUZZ_OP_MUL = 3
    BN_FUZZ_OP_DIV = 4
    BN_FUZZ_OP_MOD = 5
    BN_FUZZ_OP_EXP_MOD = 6
    BN_FUZZ_OP_LSHIFT = 7
    BN_FUZZ_OP_RSHIFT = 8
    BN_FUZZ_OP_GCD = 9
    BN_FUZZ_OP_MOD_ADD = 10
    BN_FUZZ_OP_EXP = 11
    BN_FUZZ_OP_CMP = 12
    BN_FUZZ_OP_SQR = 13
)
var g_nums = make([]*big.Int, 4)

//export go_bignum_initialize
func go_bignum_initialize() {
}

//export go_bignum_bignum_from_string
func go_bignum_bignum_from_string(s string, bn_index int) {
    g_nums[bn_index] = big.NewInt(0)
    g_nums[bn_index].SetString(s, 10)
}

//export go_bignum_string_from_bignum
func go_bignum_string_from_bignum(bn_index int) *C.char {
    s := g_nums[bn_index].String()
    return C.CString(s)
}

//export go_bignum_destroy_bignum
func go_bignum_destroy_bignum(bn_index int) {
    g_nums[bn_index] = nil
}

//export go_bignum_operation
func go_bignum_operation(op int, A int, B int, C int, D int, _opt int) int {
    if ( op == BN_FUZZ_OP_ADD ) {
        g_nums[A].Add(g_nums[B], g_nums[C])
        return 0
    } else if op == BN_FUZZ_OP_SUB {
        g_nums[A].Sub(g_nums[B], g_nums[C])
        return 0
    } else if op == BN_FUZZ_OP_MUL {
        g_nums[A].Mul(g_nums[B], g_nums[C])
        return 0
    } else if op == BN_FUZZ_OP_DIV {
        return -1
    } else if op == BN_FUZZ_OP_MOD {
        if g_nums[B].Cmp(big.NewInt(0)) >= 0 && g_nums[C].Cmp(big.NewInt(0)) > 0 {
            g_nums[A].Mod(g_nums[B], g_nums[C])
            return 0
        } else {
            return -1
        }
    } else if op == BN_FUZZ_OP_EXP_MOD {
        if g_nums[B].Cmp(big.NewInt(0)) > 0 && g_nums[C].Cmp(big.NewInt(0)) >= 0 && g_nums[D].Cmp(big.NewInt(0)) != 0 {
            tmp := big.NewInt(0)
            tmp.Exp(g_nums[B], g_nums[C], g_nums[D])
            g_nums[A] = tmp
            return 0
        } else {
            return -1
        }
    } else if op == BN_FUZZ_OP_LSHIFT {
        g_nums[A].Lsh(g_nums[B], 1)
        return 0
    } else if op == BN_FUZZ_OP_RSHIFT {
        return -1
    } else if op == BN_FUZZ_OP_GCD {
        if g_nums[B].Cmp(big.NewInt(0)) > 0 && g_nums[C].Cmp(big.NewInt(0)) > 0 {
            g_nums[A].GCD(nil, nil, g_nums[B], g_nums[C])
            return 0
        } else {
            return -1
        }
    } else if op == BN_FUZZ_OP_GCD {
        return -1
    } else if op == BN_FUZZ_OP_EXP {
        return 0
    } else if op == BN_FUZZ_OP_CMP {
        res := g_nums[B].Cmp(g_nums[C])
        if res > 0 {
            g_nums[A] = big.NewInt(1)
        } else {
            if res == 0 {
                g_nums[A] = big.NewInt(0)
            } else {
                g_nums[A] = big.NewInt(-1)
            }
        }
        return 0
    } else if op == BN_FUZZ_OP_SQR {
        g_nums[A].Exp(g_nums[B], big.NewInt(2), nil)
        return 0;
    }

    return -1
}

//export go_bignum_shutdown
func go_bignum_shutdown() {}

func main() {}
