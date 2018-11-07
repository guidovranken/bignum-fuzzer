package main

import (
	"C"
	"unsafe"
    "math/big"
	target "%v"
	dep "go-fuzz-dep"
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
    BN_FUZZ_OP_MOD_SUB = 17
    BN_FUZZ_OP_SWAP = 18
    BN_FUZZ_OP_MOD_MUL = 19
    BN_FUZZ_OP_SET_BIT = 20
)

var g_nums = make([]*target.Int, 4)

//export HolimanUint256Initialize
func HolimanUint256Initialize(coverTabPtr unsafe.Pointer, coverTabSize uint64, memcmpCBPtr unsafe.Pointer) {
	dep.Initialize(coverTabPtr, coverTabSize)
	dep.SetMemcmpCBPtr(memcmpCBPtr)
}

//export HolimanUint256BignumFromString
func HolimanUint256BignumFromString(s string, bn_index int) int {
    B, ok := new(big.Int).SetString(s, 10)
    if ok == false {
        return -1
    }
    var err bool
    g_nums[bn_index], err = target.FromBig(B)
    if err == true {
        return -1
    }

    return 0
}

//export HolimanUint256StringFromBignum
func HolimanUint256StringFromBignum(bn_index int) *C.char {
    B := g_nums[bn_index].ToBig()
    s := B.String()
    return C.CString(s)
}

func op_ADD(A int, B int, C int, D int, direct bool) int {
    if direct {
        g_nums[A].Add(g_nums[B], g_nums[C])
    } else {
        tmp := target.NewInt()
        tmp.Add(g_nums[B], g_nums[C])
        g_nums[A] = tmp
    }
    return 0
}

func op_SUB(A int, B int, C int, D int, direct bool) int {
    if direct {
        g_nums[A].Sub(g_nums[B], g_nums[C])
    } else {
        tmp := target.NewInt()
        tmp.Sub(g_nums[B], g_nums[C])
        g_nums[A] = tmp
    }
    return 0
}

func op_MUL(A int, B int, C int, D int, direct bool) int {
    if direct {
        g_nums[A].Mul(g_nums[B], g_nums[C])
    } else {
        tmp := target.NewInt()
        tmp.Mul(g_nums[B], g_nums[C])
        g_nums[A] = tmp
    }
    return 0
}

func op_DIV(A int, B int, C int, D int, direct bool) int {
    if ( g_nums[C].Cmp(target.NewInt()) != 0 ) {
        if direct {
            g_nums[A].Div(g_nums[B], g_nums[C])
        } else {
            tmp := target.NewInt()
            tmp.Div(g_nums[B], g_nums[C])
            g_nums[A] = tmp
        }
    } else {
        return -1
    }
    return 0
}

func op_MOD(A int, B int, C int, D int, direct bool) int {
    if g_nums[B].Cmp(target.NewInt()) >= 0 && g_nums[C].Cmp(target.NewInt()) > 0 {
        if direct {
            g_nums[A].Mod(g_nums[B], g_nums[C])
        } else {
            tmp := target.NewInt()
            tmp.Mod(g_nums[B], g_nums[C])
            g_nums[A] = tmp
        }
        return 0
    } else {
        return -1
    }
}

func op_EXP_MOD(A int, B int, C int, D int, direct bool) int {
    /* TODO
    if g_nums[B].Cmp(target.NewInt()) > 0 && g_nums[C].Cmp(target.NewInt()) > 0 && g_nums[D].Cmp(target.NewInt()) != 0 {
        if direct {
            g_nums[A].Exp(g_nums[B], g_nums[C], g_nums[D])
        } else {
            tmp := target.NewInt()
            tmp.Exp(g_nums[B], g_nums[C], g_nums[D])
            g_nums[A] = tmp
        }
        return 0
    } else {
        return -1
    }
    */
    return -1
}

func op_LSHIFT(A int, B int, C int, D int, direct bool) int {
    if direct {
        g_nums[A].Lsh(g_nums[B], 1)
    } else {
        tmp := target.NewInt()
        tmp.Lsh(g_nums[B], 1)
        g_nums[A] = tmp
    }
    return 0
}

func op_RSHIFT(A int, B int, C int, D int, direct bool) int {
    g_nums[A].Copy(g_nums[B])

    if direct {
        g_nums[A].Rsh(g_nums[A], 1)
    } else {
        tmp := target.NewInt()
        tmp.Rsh(g_nums[A], 1)
        g_nums[A] = tmp
    }
    return 0
}

func op_MOD_ADD(A int, B int, C int, D int, direct bool) int {
    if g_nums[D].Cmp(target.NewInt()) != 0 {
        if direct {
            g_nums[A].Add(g_nums[B], g_nums[C])
            g_nums[A].Mod(g_nums[A], g_nums[D])
        } else {
            tmp := target.NewInt()
            tmp.Add(g_nums[B], g_nums[C])
            tmp.Mod(tmp, g_nums[D])
            g_nums[A] = tmp
        }
        return 0
    } else {
        return -1
    }
}

func op_EXP(A int, B int, C int, D int, direct bool) int {
    thousand := target.NewInt().SetUint64(1000)
    if g_nums[B].Cmp(target.NewInt()) > 0 && g_nums[B].Cmp(thousand) < 0 && g_nums[C].Cmp(target.NewInt()) > 0 && g_nums[C].Cmp(thousand) < 0 {
        if direct {
            g_nums[A].Exp(g_nums[B], g_nums[C])
            return 0
        } else {
            tmp := target.NewInt()
            tmp.Exp(g_nums[B], g_nums[C])
            g_nums[A] = tmp
            return 0
        }
    } else {
        return -1
    }
    return -1
}


func op_CMP(A int, B int, C int, D int, direct bool) int {
    res := 0
    if direct {
        res = g_nums[B].Cmp(g_nums[C])
    } else {
        tmp := target.NewInt()
        tmp.Copy(g_nums[B])
        res = tmp.Cmp(g_nums[C])
    }

    if res > 0 {
        g_nums[A].SetUint64(2)
    } else {
        if res == 0 {
            g_nums[A].SetUint64(1)
        } else {
            g_nums[A].SetUint64(0)
        }
    }
    return 0
}

func op_SQR(A int, B int, C int, D int, direct bool) int {
    /* TODO
    if direct {
        g_nums[A].Exp(g_nums[B], big.NewInt(2))
    } else {
        tmp := target.NewInt()
        tmp.Exp(g_nums[B], big.NewInt(2))
        g_nums[A] = tmp
    }
    return 0
    */
    return -1
}

func op_NEG(A int, B int, C int, D int, direct bool) int {
    tmp := target.NewInt().Copy(g_nums[B])
    g_nums[B].Neg()
    g_nums[A].Copy(g_nums[B])
    g_nums[B].Copy(tmp)
    return 0
}

func op_ABS(A int, B int, C int, D int, direct bool) int {
    tmp := target.NewInt().Copy(g_nums[B])
    g_nums[B].Abs()
    g_nums[A].Copy(g_nums[B])
    g_nums[B].Copy(tmp)
    return 0
}

func op_MOD_SUB(A int, B int, C int, D int, direct bool) int {
    if g_nums[D].Cmp(target.NewInt()) != 0 {
        if direct {
            g_nums[A].Sub(g_nums[B], g_nums[C])
            g_nums[A].Mod(g_nums[A], g_nums[D])
        } else {
            tmp := target.NewInt()
            tmp.Sub(g_nums[B], g_nums[C])
            tmp.Mod(tmp, g_nums[D])
            g_nums[A] = tmp
        }
        return 0
    } else {
        return -1
    }
}

func op_SWAP(A int, B int, C int, D int, direct bool) int {
    tmp := target.NewInt().Copy(g_nums[A])
    g_nums[A].Copy(g_nums[B])
    g_nums[B].Copy(tmp)
    return 0
}

func op_MOD_MUL(A int, B int, C int, D int, direct bool) int {
    if g_nums[D].Cmp(target.NewInt()) != 0 {
        if direct {
            g_nums[A].Mul(g_nums[B], g_nums[C])
            g_nums[A].Mod(g_nums[A], g_nums[D])
        } else {
            tmp := target.NewInt()
            tmp.Mul(g_nums[B], g_nums[C])
            tmp.Mod(tmp, g_nums[D])
            g_nums[A] = tmp
        }
        return 0
    } else {
        return -1
    }
}

func op_SET_BIT(A int, B int, C int, D int, direct bool) int {
    /* Unsupported by uint256 lib
    if g_nums[A].Cmp(target.NewInt()) >= 0 && g_nums[B].Cmp(big.NewInt(1000)) <= 0 && g_nums[B].Cmp(target.NewInt()) >= 0 {
        pos := g_nums[B].Int64()

        if direct {
            g_nums[A].SetBit(g_nums[A], int(pos), 1)
        } else {
            tmp := g_nums[A]
            tmp.SetBit(g_nums[A], int(pos), 1)
            g_nums[A] = tmp
        }

        return 0
    } else {
        return -1
    }
    */
    return -1
}

//export HolimanUint256BignumOperation
func HolimanUint256BignumOperation(op int, A int, B int, C int, D int, opt int) int {
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
    op == BN_FUZZ_OP_RSHIFT { return op_RSHIFT(A, B, C, D, direct) } else if
    op == BN_FUZZ_OP_MOD_ADD { return op_MOD_ADD(A, B, C, D, direct) } else if
    op == BN_FUZZ_OP_EXP { return op_EXP(A, B, C, D, direct); } else if
    op == BN_FUZZ_OP_CMP { return op_CMP(A, B, C, D, direct) } else if
    op == BN_FUZZ_OP_SQR { return op_SQR(A, B, C, D, direct) } else if
    op == BN_FUZZ_OP_NEG { return op_NEG(A, B, C, D, direct) } else if
    op == BN_FUZZ_OP_ABS { return op_ABS(A, B, C, D, direct) } else if
    op == BN_FUZZ_OP_MOD_SUB { return op_MOD_SUB(A, B, C, D, direct) } else if
    op == BN_FUZZ_OP_SWAP { return op_SWAP(A, B, C, D, direct) } else if
    op == BN_FUZZ_OP_MOD_MUL { return op_MOD_MUL(A, B, C, D, direct) } else if
    op == BN_FUZZ_OP_SET_BIT { return op_SET_BIT(A, B, C, D, direct) }

    return -1
}

func main() {
}
