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
    BN_FUZZ_OP_NEG = 14
    BN_FUZZ_OP_ABS = 15
    BN_FUZZ_OP_IS_PRIME = 16
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

func op_ADD(A int, B int, C int, D int, direct bool) int {
    if direct {
        g_nums[A].Add(g_nums[B], g_nums[C])
    } else {
        tmp := big.NewInt(0)
        tmp.Add(g_nums[B], g_nums[C])
        g_nums[A] = tmp
    }
    return 0
}

func op_SUB(A int, B int, C int, D int, direct bool) int {
    if direct {
        g_nums[A].Sub(g_nums[B], g_nums[C])
    } else {
        tmp := big.NewInt(0)
        tmp.Sub(g_nums[B], g_nums[C])
        g_nums[A] = tmp
    }
    return 0
}

func op_MUL(A int, B int, C int, D int, direct bool) int {
    if direct {
        g_nums[A].Mul(g_nums[B], g_nums[C])
    } else {
        tmp := big.NewInt(0)
        tmp.Mul(g_nums[B], g_nums[C])
        g_nums[A] = tmp
    }
    return 0
}

func op_DIV(A int, B int, C int, D int, direct bool) int {
    if ( g_nums[C].Cmp(big.NewInt(0)) != 0 ) {
        if direct {
            g_nums[A].Div(g_nums[B], g_nums[C])
        } else {
            tmp := big.NewInt(0)
            tmp.Div(g_nums[B], g_nums[C])
            g_nums[A] = tmp
        }
    } else {
        return -1
    }
    return 0
}

func op_MOD(A int, B int, C int, D int, direct bool) int {
    if g_nums[B].Cmp(big.NewInt(0)) >= 0 && g_nums[C].Cmp(big.NewInt(0)) > 0 {
        if direct {
            g_nums[A].Mod(g_nums[B], g_nums[C])
        } else {
            tmp := big.NewInt(0)
            tmp.Mod(g_nums[B], g_nums[C])
            g_nums[A] = tmp
        }
        return 0
    } else {
        return -1
    }
}

func op_EXP_MOD(A int, B int, C int, D int, direct bool) int {
    if g_nums[B].Cmp(big.NewInt(0)) > 0 && g_nums[C].Cmp(big.NewInt(0)) >= 0 && g_nums[D].Cmp(big.NewInt(0)) != 0 {
        if direct {
            g_nums[A].Exp(g_nums[B], g_nums[C], g_nums[D])
        } else {
            tmp := big.NewInt(0)
            tmp.Exp(g_nums[B], g_nums[C], g_nums[D])
            g_nums[A] = tmp
        }
        return 0
    } else {
        return -1
    }
}

func op_LSHIFT(A int, B int, C int, D int, direct bool) int {
    if direct {
        g_nums[A].Lsh(g_nums[B], 1)
    } else {
        tmp := big.NewInt(0)
        tmp.Lsh(g_nums[B], 1)
        g_nums[A] = tmp
    }
    return 0
}

func op_GCD(A int, B int, C int, D int, direct bool) int {
    if g_nums[B].Cmp(big.NewInt(0)) > 0 && g_nums[C].Cmp(big.NewInt(0)) > 0 {
        if direct {
            g_nums[A].GCD(nil, nil, g_nums[B], g_nums[C])
        } else {
            tmp := big.NewInt(0)
            tmp.GCD(nil, nil, g_nums[B], g_nums[C])
            g_nums[A] = tmp
        }
        return 0
    } else {
        return -1
    }
}

func op_EXP(A int, B int, C int, D int, direct bool) int {
    thousand := big.NewInt(1000)
    if g_nums[B].Cmp(big.NewInt(0)) > 0 && g_nums[B].Cmp(thousand) < 0 && g_nums[C].Cmp(big.NewInt(0)) > 0 && g_nums[C].Cmp(thousand) < 0 {
        if direct {
            g_nums[A].Exp(g_nums[B], g_nums[C], nil)
            return 0
        } else {
            tmp := big.NewInt(0)
            tmp.Exp(g_nums[B], g_nums[C], nil)
            g_nums[A] = tmp
            return 0
        }
    } else {
        return -1
    }
}


func op_CMP(A int, B int, C int, D int, _direct bool) int {
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
}

func op_SQR(A int, B int, C int, D int, direct bool) int {
    if direct {
        g_nums[A].Exp(g_nums[B], big.NewInt(2), nil)
    } else {
        tmp := big.NewInt(0)
        tmp.Exp(g_nums[B], big.NewInt(2), nil)
        g_nums[A] = tmp
    }
    return 0
}

func op_NEG(A int, B int, C int, D int, direct bool) int {
    if direct {
        g_nums[A].Neg(g_nums[B])
    } else {
        tmp := big.NewInt(0)
        tmp.Neg(g_nums[B])
        g_nums[A] = tmp
    }
    return 0
}

func op_ABS(A int, B int, C int, D int, direct bool) int {
    if direct {
        g_nums[A].Abs(g_nums[B])
    } else {
        tmp := big.NewInt(0)
        tmp.Abs(g_nums[B])
        g_nums[A] = tmp
    }
    return 0
}

func op_IS_PRIME(A int, B int, C int, D int, direct bool) int {
    /* "ProbablyPrime is 100% accurate for inputs less than 2⁶⁴."
     * https://golang.org/pkg/math/big/#Int.ProbablyPrime
    */
    max64 := big.NewInt(0).Lsh( big.NewInt(1), 64 )
    max64.Sub(max64, big.NewInt(1))
    if g_nums[A].Cmp(max64) < 0 {
        is_prime := g_nums[B].ProbablyPrime(0)
        if is_prime {
            g_nums[A] = big.NewInt(1)
        } else {
            g_nums[A] = big.NewInt(0)
        }
        return 0
    } else {
        return -1
    }
}
//export go_bignum_operation
func go_bignum_operation(op int, A int, B int, C int, D int, opt int) int {
    direct := false
    if opt & 1 == 1 {
        direct = true
    }
    if ( op == BN_FUZZ_OP_ADD ) { return op_ADD(A, B, C, D, direct) } else if
    op == BN_FUZZ_OP_SUB { return op_SUB(A, B, C, D, direct) } else if
    op == BN_FUZZ_OP_MUL { return op_MUL(A, B, C, D, direct) } else if
    op == BN_FUZZ_OP_DIV { return op_DIV(A, B, C, D, direct) } else if
    op == BN_FUZZ_OP_MOD { return op_MOD(A, B, C, D, direct) } else if
    op == BN_FUZZ_OP_EXP_MOD { return op_EXP_MOD(A, B, C, D, direct) } else if
    op == BN_FUZZ_OP_LSHIFT { return op_LSHIFT(A, B, C, D, direct) } else if
    op == BN_FUZZ_OP_RSHIFT { return -1 } else if
    op == BN_FUZZ_OP_GCD { return op_GCD(A, B, C, D, direct) } else if
    op == BN_FUZZ_OP_EXP { return op_EXP(A, B, C, D, direct); } else if
    op == BN_FUZZ_OP_CMP { return op_CMP(A, B, C, D, direct) } else if
    op == BN_FUZZ_OP_SQR { return op_SQR(A, B, C, D, direct) } else if
    op == BN_FUZZ_OP_NEG { return op_NEG(A, B, C, D, direct) } else if
    op == BN_FUZZ_OP_ABS { return op_ABS(A, B, C, D, direct) } else if
    op == BN_FUZZ_OP_IS_PRIME { return op_IS_PRIME(A, B, C, D, direct) }

    return -1
}

//export go_bignum_shutdown
func go_bignum_shutdown() {}

func main() {}
