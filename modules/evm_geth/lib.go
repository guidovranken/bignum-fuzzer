package main

import "C"

import (
    "math/big"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/math"
)

const (
    BN_FUZZ_OP_ETH_ADD = 1
    BN_FUZZ_OP_ETH_SUB = 2
    BN_FUZZ_OP_ETH_MUL = 3
    BN_FUZZ_OP_ETH_DIV = 4
    BN_FUZZ_OP_ETH_SDIV = 5
    BN_FUZZ_OP_ETH_MOD = 6
    BN_FUZZ_OP_ETH_SMOD = 7
    BN_FUZZ_OP_ETH_EXP = 8
    BN_FUZZ_OP_ETH_SIGNEXTEND = 9
    BN_FUZZ_OP_ETH_NOT = 10
    BN_FUZZ_OP_ETH_LT = 11
    BN_FUZZ_OP_ETH_GT = 12
    BN_FUZZ_OP_ETH_SLT = 13
    BN_FUZZ_OP_ETH_SGT = 14
    BN_FUZZ_OP_ETH_EQ = 15
    BN_FUZZ_OP_ETH_ISZERO = 16
    BN_FUZZ_OP_ETH_AND = 17
    BN_FUZZ_OP_ETH_OR = 18
    BN_FUZZ_OP_ETH_XOR = 19
    BN_FUZZ_OP_ETH_BYTE = 20
    BN_FUZZ_OP_ETH_ADDMOD = 21
    BN_FUZZ_OP_ETH_MULMOD = 22
)

var (
	bigZero                  = new(big.Int)
    max256, _                = new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", 16)
)

type Stack struct {
	data []*big.Int
}
func (st *Stack) pop() (ret *big.Int) {
	ret = st.data[len(st.data)-1]
	st.data = st.data[:len(st.data)-1]
	return
}
func (st *Stack) push(d *big.Int) {
	st.data = append(st.data, d)
}
func (st *Stack) len() int {
	return len(st.data)
}

func (st *Stack) peek() *big.Int {
	return st.data[st.len()-1]
}

var g_nums = make([]*big.Int, 4)

//export go_bignum_initialize
func go_bignum_initialize() {
}

//export go_bignum_bignum_from_string
func go_bignum_bignum_from_string(s string, bn_index int) int {
    g_nums[bn_index] = big.NewInt(0)
    g_nums[bn_index].SetString(s, 10)
    if g_nums[bn_index].Cmp(max256) > 0 {
        return -1
    }
    return 0
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

func op_ADD(stack* Stack) int {
	x, y := stack.pop(), stack.pop()
	stack.push(math.U256(x.Add(x, y)))

    return 0
}

func op_SUB(stack* Stack) int {
	x, y := stack.pop(), stack.pop()
	stack.push(math.U256(x.Sub(x, y)))

	return 0
}

func op_DIV(stack* Stack) int {
	x, y := stack.pop(), stack.pop()
	if y.Sign() != 0 {
		stack.push(math.U256(x.Div(x, y)))
	} else {
		stack.push(new(big.Int))
	}

	return 0
}

func op_SDIV(stack* Stack) int {
	x, y := math.S256(stack.pop()), math.S256(stack.pop())
	if y.Sign() == 0 {
		stack.push(new(big.Int))
        return 0
	} else {
		n := new(big.Int)
		//if evm.interpreter.intPool.get().Mul(x, y).Sign() < 0 {
		if new(big.Int).Mul(x, y).Sign() < 0 {
			n.SetInt64(-1)
		} else {
			n.SetInt64(1)
		}

		res := x.Div(x.Abs(x), y.Abs(y))
		res.Mul(res, n)

		stack.push(math.U256(res))
	}

    return 0
}

func op_MOD(stack* Stack) int {
	x, y := stack.pop(), stack.pop()
	if y.Sign() == 0 {
		stack.push(new(big.Int))
	} else {
		stack.push(math.U256(x.Mod(x, y)))
	}

    return 0
}

func op_SMOD(stack* Stack) int {
	x, y := math.S256(stack.pop()), math.S256(stack.pop())

	if y.Sign() == 0 {
		stack.push(new(big.Int))
	} else {
		n := new(big.Int)
		if x.Sign() < 0 {
			n.SetInt64(-1)
		} else {
			n.SetInt64(1)
		}

		res := x.Mod(x.Abs(x), y.Abs(y))
		res.Mul(res, n)

		stack.push(math.U256(res))
	}

    return 0
}

func op_EXP(stack* Stack) int {
	base, exponent := stack.pop(), stack.pop()
	stack.push(math.Exp(base, exponent))

    return 0
}

func op_SIGNEXTEND(stack* Stack) int {
	back := stack.pop()
	if back.Cmp(big.NewInt(31)) < 0 {
		bit := uint(back.Uint64()*8 + 7)
		num := stack.pop()
		mask := back.Lsh(common.Big1, bit)
		mask.Sub(mask, common.Big1)
		if num.Bit(int(bit)) > 0 {
			num.Or(num, mask.Not(mask))
		} else {
			num.And(num, mask)
		}

		stack.push(math.U256(num))
	}

    return 0
}


func op_NOT(stack* Stack) int {
	x := stack.pop()
	stack.push(math.U256(x.Not(x)))

    return 0
}

func op_LT(stack* Stack) int {
	x, y := stack.pop(), stack.pop()
	if x.Cmp(y) < 0 {
		//stack.push(evm.interpreter.intPool.get().SetUint64(1))
		stack.push(new(big.Int).SetUint64(1))
	} else {
		stack.push(new(big.Int))
	}

    return 0
}

func op_GT(stack* Stack) int {
	x, y := stack.pop(), stack.pop()
	if x.Cmp(y) > 0 {
		//stack.push(evm.interpreter.intPool.get().SetUint64(1))
		stack.push(new(big.Int).SetUint64(1))
	} else {
		stack.push(new(big.Int))
	}

    return 0
}

func op_SLT(stack* Stack) int {
	x, y := math.S256(stack.pop()), math.S256(stack.pop())
	if x.Cmp(math.S256(y)) < 0 {
		//stack.push(evm.interpreter.intPool.get().SetUint64(1))
		stack.push(new(big.Int).SetUint64(1))
	} else {
		stack.push(new(big.Int))
	}

    return 0
}

func op_SGT(stack* Stack) int {
	x, y := math.S256(stack.pop()), math.S256(stack.pop())
	if x.Cmp(y) > 0 {
		stack.push(new(big.Int).SetUint64(1))
	} else {
		stack.push(new(big.Int))
	}

    return 0
}

func op_EQ(stack* Stack) int {
	x, y := stack.pop(), stack.pop()
	if x.Cmp(y) == 0 {
		stack.push(new(big.Int).SetUint64(1))
	} else {
		stack.push(new(big.Int))
	}

    return 0
}

func op_ISZERO(stack* Stack) int {
	x := stack.pop()
	if x.Sign() > 0 {
		stack.push(new(big.Int))
	} else {
		stack.push(new(big.Int).SetUint64(1))
	}

    return 0
}

func op_AND(stack* Stack) int {
	x, y := stack.pop(), stack.pop()
	stack.push(x.And(x, y))

    return 0
}

func op_OR(stack* Stack) int {
	x, y := stack.pop(), stack.pop()
	stack.push(x.Or(x, y))

    return 0
}

func op_XOR(stack* Stack) int {
	x, y := stack.pop(), stack.pop()
	stack.push(x.Xor(x, y))

    return 0
}

func op_BYTE(stack* Stack) int {
	th, val := stack.pop(), stack.peek()
	if th.Cmp(common.Big32) < 0 {
		b := math.Byte(val, 32, int(th.Int64()))
		val.SetUint64(uint64(b))
	} else {
		val.SetUint64(0)
	}

    return 0
}

func op_ADDMOD(stack* Stack) int {
	x, y, z := stack.pop(), stack.pop(), stack.pop()
	if z.Cmp(bigZero) > 0 {
		add := x.Add(x, y)
		add.Mod(add, z)
		stack.push(math.U256(add))
	} else {
		stack.push(new(big.Int))
	}

    return 0
}

func op_MULMOD(stack* Stack) int {
	x, y, z := stack.pop(), stack.pop(), stack.pop()
	if z.Cmp(bigZero) > 0 {
		mul := x.Mul(x, y)
		mul.Mod(mul, z)
		stack.push(math.U256(mul))
	} else {
		stack.push(new(big.Int))
	}
    return 0
}

func set_num(index int, num *big.Int) {
    if index == 0 { g_nums[0].Set(num) } else if
    index == 1 { g_nums[1].Set(num) } else if
    index == 2 { g_nums[2].Set(num) } else if
    index == 3 { g_nums[3].Set(num) } else {
        panic("Invalid index in set_num")
    }
}

func sync_stack(stack* Stack) {
    stack_size := stack.len()
    i := stack_size - 1
    for i >= 0 {
        set_num(i, stack.pop());
        i -= 1;
    }
    i = stack_size
    for i < 4 {
        set_num(i, new(big.Int));
        i += 1;
    }
}

//export go_bignum_operation
func go_bignum_operation(op int, A int, B int, C int, D int, opt int) int {
    stack := new(Stack)
    defer sync_stack(stack)
    stack.push( new(big.Int).Set( g_nums[A] ) )
    stack.push( new(big.Int).Set( g_nums[B] ) )
    stack.push( new(big.Int).Set( g_nums[C] ) )
    stack.push( new(big.Int).Set( g_nums[D] ) )

    if op == BN_FUZZ_OP_ETH_ADD { return op_ADD(stack) } else if
    op == BN_FUZZ_OP_ETH_SUB { return op_SUB(stack) } else if
    op == BN_FUZZ_OP_ETH_DIV { return op_DIV(stack) } else if
    op == BN_FUZZ_OP_ETH_SDIV { return op_SDIV(stack) } else if
    op == BN_FUZZ_OP_ETH_MOD { return op_MOD(stack) } else if
    op == BN_FUZZ_OP_ETH_SMOD { return op_SMOD(stack) } else if
    op == BN_FUZZ_OP_ETH_EXP { return op_EXP(stack) } else if
    op == BN_FUZZ_OP_ETH_SIGNEXTEND { return op_SIGNEXTEND(stack) } else if
    op == BN_FUZZ_OP_ETH_NOT { return op_NOT(stack) } else if
    op == BN_FUZZ_OP_ETH_LT { return op_LT(stack) } else if
    op == BN_FUZZ_OP_ETH_GT { return op_GT(stack) } else if
    op == BN_FUZZ_OP_ETH_SLT { return op_SLT(stack) } else if
    op == BN_FUZZ_OP_ETH_SGT { return op_SGT(stack) } else if
    op == BN_FUZZ_OP_ETH_EQ { return op_EQ(stack) } else if
    op == BN_FUZZ_OP_ETH_ISZERO { return op_ISZERO(stack) } else if
    op == BN_FUZZ_OP_ETH_AND { return op_AND(stack) } else if
    op == BN_FUZZ_OP_ETH_OR { return op_OR(stack) } else if
    op == BN_FUZZ_OP_ETH_XOR { return op_XOR(stack) } else if
    op == BN_FUZZ_OP_ETH_BYTE { return op_BYTE(stack) } else if
    op == BN_FUZZ_OP_ETH_ADDMOD { return op_ADDMOD(stack) } else if
    op == BN_FUZZ_OP_ETH_MULMOD { return op_MULMOD(stack) }

    return -1
}

//export go_bignum_shutdown
func go_bignum_shutdown() {}

func main() {}
