#![feature(libc)]
#[macro_use]
extern crate lazy_static;
extern crate libc;
extern crate num;
extern crate ethcore_bigint as bigint;
use libc::{c_int, c_char};
use num::{Num, BigInt, Zero}; 
use std::sync::Mutex;
use std::ffi::CStr;
use std::ffi::CString;
use bigint::prelude::uint::U256;
use bigint::prelude::uint::U512;
use bigint::hash::H256;

mod stack;
use self::stack::{Stack, VecStack};

const ONE: U256 = U256([1, 0, 0, 0]);
const TWO: U256 = U256([2, 0, 0, 0]);
const TWO_POW_5: U256 = U256([0x20, 0, 0, 0]);
const TWO_POW_8: U256 = U256([0x100, 0, 0, 0]);
const TWO_POW_16: U256 = U256([0x10000, 0, 0, 0]);
const TWO_POW_24: U256 = U256([0x1000000, 0, 0, 0]);
const TWO_POW_64: U256 = U256([0, 0x1, 0, 0]); // 0x1 00000000 00000000
const TWO_POW_96: U256 = U256([0, 0x100000000, 0, 0]); //0x1 00000000 00000000 00000000
const TWO_POW_224: U256 = U256([0, 0, 0, 0x100000000]); //0x1 00000000 00000000 00000000 00000000 00000000 00000000 00000000
const TWO_POW_248: U256 = U256([0, 0, 0, 0x100000000000000]); //0x1 00000000 00000000 00000000 00000000 00000000 00000000 00000000 000000

lazy_static! {
    static ref NUM1: Mutex<U256> = Mutex::new(U256::from(0));
    static ref NUM2: Mutex<U256> = Mutex::new(U256::from(0));
    static ref NUM3: Mutex<U256> = Mutex::new(U256::from(0));
    static ref NUM4: Mutex<U256> = Mutex::new(U256::from(0));
}
#[no_mangle]
pub extern fn rust_bignum_initialize() {
}

#[no_mangle]
pub extern fn rust_bignum_bignum_from_string(s: *const c_char, bn_index: c_int) -> c_int {
    //let base = BigInt::from_str_radix("0", 10).unwrap();
    //base.from_str_radix("0", 10).unwrap();
    //NUM1.from_str_radix("56666666666666666666", 10).unwrap()
    //NUM1.lock().unwrap().from_str_radix("56666666666666666666", 10)
    let s2 = unsafe {
        CStr::from_ptr(s).to_str().unwrap()
    };
    let mut num1 = NUM1.lock().unwrap();
    let mut num2 = NUM2.lock().unwrap();
    let mut num3 = NUM3.lock().unwrap();
    let mut num4 = NUM4.lock().unwrap();

    /* From string to BigInt */
    let num = BigInt::from_str_radix(s2, 10).unwrap();
    if num < Zero::zero() {
        /* Don't accept negative numbers */
        return -1;
    }

    /* From BigInt to Vec */
    let mut b = num.to_bytes_be().1;
    if b.len() > 32 {
        /* Don't accept numbers larger than 256 bits */
        return -1;
    }

    let mut b2: Vec<u8> = vec![0; 32 - b.len()];
    b2.append(&mut b);

    /* From Vec to U256 */
    let numu256 = U256::from(H256::from_slice(&b2));

    match bn_index {
        0 => { *num1 = numu256; },
        1 => { *num2 = numu256; },
        2 => { *num3 = numu256; },
        3 => { *num4 = numu256; },
        _ => panic!("invalid bn_index"),
    }

    return 0;
}
#[no_mangle]
pub extern fn rust_bignum_string_from_bignum(bn_index: c_int) -> *const c_char{
    let s = match bn_index {
        0 => { format!("{:?}", *(NUM1.lock().unwrap())) },
        1 => { format!("{:?}", *(NUM2.lock().unwrap())) },
        2 => { format!("{:?}", *(NUM3.lock().unwrap())) },
        3 => { format!("{:?}", *(NUM4.lock().unwrap())) },
        _ => panic!("invalid bn_index"),
    };
    let c_str_s = CString::new(s).unwrap();
    c_str_s.into_raw()
}

#[no_mangle]
pub extern fn rust_bignum_free_string(s: *mut c_char) {
    unsafe {
        if s.is_null() { return }
        CString::from_raw(s)
    };
}

fn bool_to_u256(val: bool) -> U256 {
    if val {
        U256::one()
    } else {
        U256::zero()
    }
}

fn set_sign(value: U256, sign: bool) -> U256 {
	if sign {
		(!U256::zero() ^ value).overflowing_add(U256::one()).0
	} else {
		value
	}
}

fn get_and_reset_sign(value: U256) -> (U256, bool) {
	let U256(arr) = value;
	let sign = arr[3].leading_zeros() == 0;
	(set_sign(value, sign), sign)
}

fn is_zero(val: &U256) -> bool {
    val.is_zero()
}

fn op_add(stack: &mut Stack<U256>) {
    let a = stack.pop_back();
    let b = stack.pop_back();
    stack.push(a.overflowing_add(b).0);
}

fn op_sub(stack: &mut Stack<U256>) {
    let a = stack.pop_back();
    let b = stack.pop_back();
    stack.push(a.overflowing_sub(b).0);
}

fn op_mul(stack: &mut Stack<U256>) {
    let a = stack.pop_back();
    let b = stack.pop_back();
    stack.push(a.overflowing_mul(b).0);
}

fn op_div(stack: &mut Stack<U256>) {
    let a = stack.pop_back();
    let b = stack.pop_back();
    stack.push(if !is_zero(&b) {
        match b {
            ONE => a,
            TWO => a >> 1,
            TWO_POW_5 => a >> 5,
            TWO_POW_8 => a >> 8,
            TWO_POW_16 => a >> 16,
            TWO_POW_24 => a >> 24,
            TWO_POW_64 => a >> 64,
            TWO_POW_96 => a >> 96,
            TWO_POW_224 => a >> 224,
            TWO_POW_248 => a >> 248,
            _ => a.overflowing_div(b).0,
        }
    } else {
        U256::zero()
    });
}

fn op_sdiv(stack: &mut Stack<U256>) {
    let (a, sign_a) = get_and_reset_sign(stack.pop_back());
    let (b, sign_b) = get_and_reset_sign(stack.pop_back());

    // -2^255
    let min = (U256::one() << 255) - U256::one();
    stack.push(if is_zero(&b) {
        U256::zero()
    } else if a == min && b == !U256::zero() {
        min
    } else {
        let c = a.overflowing_div(b).0;
        set_sign(c, sign_a ^ sign_b)
    });
}

fn op_mod(stack: &mut Stack<U256>) {
    let a = stack.pop_back();
    let b = stack.pop_back();
    stack.push(if !is_zero(&b) {
        a.overflowing_rem(b).0
    } else {
        U256::zero()
    });
}

fn op_smod(stack: &mut Stack<U256>) {
    let ua = stack.pop_back();
    let ub = stack.pop_back();
    let (a, sign_a) = get_and_reset_sign(ua);
    let b = get_and_reset_sign(ub).0;

    stack.push(if !is_zero(&b) {
        let c = a.overflowing_rem(b).0;
        set_sign(c, sign_a)
    } else {
        U256::zero()
    });
}

fn op_exp(stack: &mut Stack<U256>) {
    let base = stack.pop_back();
    let expon = stack.pop_back();
    let res = base.overflowing_pow(expon).0;
    stack.push(res);
}

fn op_signextend(stack: &mut Stack<U256>) {
    let bit = stack.pop_back();
    if bit < U256::from(32) {
        let number = stack.pop_back();
        let bit_position = (bit.low_u64() * 8 + 7) as usize;

        let bit = number.bit(bit_position);
        let mask = (U256::one() << bit_position) - U256::one();
        stack.push(if bit {
            number | !mask
        } else {
            number & mask
        });
    }
}

fn op_not(stack: &mut Stack<U256>) {
    let a = stack.pop_back();
    stack.push(!a);
}

fn op_lt(stack: &mut Stack<U256>) {
    let a = stack.pop_back();
    let b = stack.pop_back();
    stack.push(bool_to_u256(a < b));
}

fn op_gt(stack: &mut Stack<U256>) {
    let a = stack.pop_back();
    let b = stack.pop_back();
    stack.push(bool_to_u256(a > b));
}

fn op_slt(stack: &mut Stack<U256>) {
    let (a, neg_a) = get_and_reset_sign(stack.pop_back());
    let (b, neg_b) = get_and_reset_sign(stack.pop_back());

    let is_positive_lt = a < b && !(neg_a | neg_b);
    let is_negative_lt = a > b && (neg_a & neg_b);
    let has_different_signs = neg_a && !neg_b;

    stack.push(bool_to_u256(is_positive_lt | is_negative_lt | has_different_signs));
}

fn op_sgt(stack: &mut Stack<U256>) {
    let (a, neg_a) = get_and_reset_sign(stack.pop_back());
    let (b, neg_b) = get_and_reset_sign(stack.pop_back());

    let is_positive_gt = a > b && !(neg_a | neg_b);
    let is_negative_gt = a < b && (neg_a & neg_b);
    let has_different_signs = !neg_a && neg_b;

    stack.push(bool_to_u256(is_positive_gt | is_negative_gt | has_different_signs));
}

fn op_eq(stack: &mut Stack<U256>) {
    let a = stack.pop_back();
    let b = stack.pop_back();
    stack.push(bool_to_u256(a == b));
}

fn op_iszero(stack: &mut Stack<U256>) {
    let a = stack.pop_back();
    stack.push(bool_to_u256(is_zero(&a)));
}

fn op_and(stack: &mut Stack<U256>) {
    let a = stack.pop_back();
    let b = stack.pop_back();
    stack.push(a & b);
}

fn op_or(stack: &mut Stack<U256>) {
    let a = stack.pop_back();
    let b = stack.pop_back();
    stack.push(a | b);
}

fn op_xor(stack: &mut Stack<U256>) {
    let a = stack.pop_back();
    let b = stack.pop_back();
    stack.push(a ^ b);
}

fn op_byte(stack: &mut Stack<U256>) {
    let word = stack.pop_back();
    let val = stack.pop_back();
    let byte = match word < U256::from(32) {
        true => (val >> (8 * (31 - word.low_u64() as usize))) & U256::from(0xff),
             false => U256::zero()
    };
    stack.push(byte);
}

fn op_addmod(stack: &mut Stack<U256>) {
    let a = stack.pop_back();
    let b = stack.pop_back();
    let c = stack.pop_back();

    stack.push(if !is_zero(&c) {
        // upcast to 512
        let a5 = U512::from(a);
        let res = a5.overflowing_add(U512::from(b)).0;
        let x = res.overflowing_rem(U512::from(c)).0;
        U256::from(x)
    } else {
        U256::zero()
    });
}

fn op_mulmod(stack: &mut Stack<U256>) {
    let a = stack.pop_back();
    let b = stack.pop_back();
    let c = stack.pop_back();

    stack.push(if !is_zero(&c) {
        let a5 = U512::from(a);
        let res = a5.overflowing_mul(U512::from(b)).0;
        let x = res.overflowing_rem(U512::from(c)).0;
        U256::from(x)
    } else {
        U256::zero()
    });
}

fn set_num(index: i32, u256: U256) {
    let mut num1 = NUM1.lock().unwrap();
    let mut num2 = NUM2.lock().unwrap();
    let mut num3 = NUM3.lock().unwrap();
    let mut num4 = NUM4.lock().unwrap();
    match index {
        0 => { *num1 = u256; },
        1 => { *num2 = u256; },
        2 => { *num3 = u256; },
        3 => { *num4 = u256; },
        _ => { panic!("invalid index in set_num") }
    }
}

#[no_mangle]
pub extern fn rust_bignum_operation(op: c_int, _opt: c_int) -> c_int {
    let mut ret = -1;
    let mut stack = VecStack::with_capacity(100, U256::zero());

    stack.push( *(NUM1.lock().unwrap()) );
    stack.push( *(NUM2.lock().unwrap()) );
    stack.push( *(NUM3.lock().unwrap()) );
    stack.push( *(NUM4.lock().unwrap()) );

    match op {
        1 => { /* BN_FUZZ_OP_ETH_ADD = 1 */
            op_add(&mut stack);
            ret = 0;
        }
        2 => { /* BN_FUZZ_OP_ETH_SUB = 2 */
            op_sub(&mut stack);
            ret = 0;
        }
        3 => { /* BN_FUZZ_OP_ETH_MUL = 3 */
            op_mul(&mut stack);
            ret = 0;
        }
        4 => { /* BN_FUZZ_OP_ETH_DIV = 4 */
            op_div(&mut stack);
            ret = 0;
        }
        5 => { /* BN_FUZZ_OP_ETH_SDIV = 5 */
            op_sdiv(&mut stack);
            ret = 0;
        }
        6 => { /* BN_FUZZ_OP_ETH_MOD = 6 */
            op_mod(&mut stack);
            ret = 0;
        }
        7 => { /* BN_FUZZ_OP_ETH_SMOD = 7 */
            op_smod(&mut stack);
            ret = 0;
        }
        8 => { /* BN_FUZZ_OP_ETH_EXP = 8 */
            op_exp(&mut stack);
            ret = 0;
        }
        9 => { /* BN_FUZZ_OP_ETH_SIGNEXTEND = 9 */
            op_signextend(&mut stack);
            ret = 0;
        }
        10 => { /* BN_FUZZ_OP_ETH_NOT = 10 */
            op_not(&mut stack);
            ret = 0;
        }
        11 => { /* BN_FUZZ_OP_ETH_LT = 11 */
            op_lt(&mut stack);
            ret = 0;
        }
        12 => { /* BN_FUZZ_OP_ETH_GT = 12 */
            op_gt(&mut stack);
            ret = 0;
        }
        13 => { /* BN_FUZZ_OP_ETH_SLT = 13 */
            op_slt(&mut stack);
            ret = 0;
        }
        14 => { /* BN_FUZZ_OP_ETH_SGT = 14 */
            op_sgt(&mut stack);
            ret = 0;
        }
        15 => { /* BN_FUZZ_OP_ETH_EQ = 15 */
            op_eq(&mut stack);
            ret = 0;
        }
        16 => { /* BN_FUZZ_OP_ETH_ISZERO = 16 */
            op_iszero(&mut stack);
            ret = 0;
        }
        17 => { /* BN_FUZZ_OP_ETH_AND = 17 */
            op_and(&mut stack);
            ret = 0;
        }
        18 => { /* BN_FUZZ_OP_ETH_OR = 18 */
            op_or(&mut stack);
            ret = 0;
        }
        19 => { /* BN_FUZZ_OP_ETH_XOR = 19 */
            op_xor(&mut stack);
            ret = 0;
        }
        20 => { /* BN_FUZZ_OP_ETH_BYTE = 20 */
            op_byte(&mut stack);
            ret = 0;
        }
        21 => { /* BN_FUZZ_OP_ETH_ADDMOD = 21 */
            op_addmod(&mut stack);
            ret = 0;
        }
        22 => { /* BN_FUZZ_OP_ETH_MULMOD = 22 */
            op_mulmod(&mut stack);
            ret = 0;
        }
        _ => {
            ret = -1;
        }
    }

    let stack_size: i32 = stack.size() as i32;
    let mut i: i32 = stack_size - 1;
    while i >= 0 {
        set_num(i, stack.pop_back());
        i -= 1;
    }
    i = stack_size;
    while i < 4 {
        set_num(i, U256::from(0));
        i += 1;
    }
    return ret;
}

#[no_mangle]
pub extern fn rust_bignum_shutdown() {
}
