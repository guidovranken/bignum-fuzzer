#![feature(libc)]
#[macro_use]
extern crate lazy_static;
extern crate libc;
extern crate num;
use libc::{c_int, c_char};
use num::{Num, BigInt, Zero, One, Integer, pow};
use std::sync::Mutex;
use std::ffi::CStr;
use std::ffi::CString;
use std::ops::{Add, Sub, Mul, Div, Rem, Shl, Shr, Neg};
use num::ToPrimitive;
use num::Signed;
lazy_static! {
    static ref NUM1: Mutex<BigInt> = Mutex::new(BigInt::from_str_radix("0", 10).unwrap());
    static ref NUM2: Mutex<BigInt> = Mutex::new(BigInt::from_str_radix("0", 10).unwrap());
    static ref NUM3: Mutex<BigInt> = Mutex::new(BigInt::from_str_radix("0", 10).unwrap());
    static ref NUM4: Mutex<BigInt> = Mutex::new(BigInt::from_str_radix("0", 10).unwrap());
}
#[no_mangle]
pub extern fn rust_bignum_initialize() {
}

#[no_mangle]
pub extern fn rust_bignum_bignum_from_string(s: *const c_char, bn_index: c_int) {
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
    match bn_index {
        0 => {
            *num1 = BigInt::from_str_radix(s2, 10).unwrap();
        },
        1 => {
            *num2 = BigInt::from_str_radix(s2, 10).unwrap();
        },
        2 => {
            *num3 = BigInt::from_str_radix(s2, 10).unwrap();
        },
        3 => {
            *num4 = BigInt::from_str_radix(s2, 10).unwrap();
        },
        _ => panic!("invalid bn_index"),
    }
}

#[no_mangle]
pub extern fn rust_bignum_string_from_bignum(bn_index: c_int) -> *const c_char{
    let s = match bn_index {
        0 => { NUM1.lock().unwrap().to_str_radix(10) },
        1 => { NUM2.lock().unwrap().to_str_radix(10) },
        2 => { NUM3.lock().unwrap().to_str_radix(10) },
        3 => { NUM4.lock().unwrap().to_str_radix(10) },
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

/* Taken from Parity */
fn modexp(mut base: BigInt, mut exp: BigInt, modulus: BigInt) -> BigInt {
	use num::Integer;

	if modulus <= BigInt::one() { // n^m % 0 || n^m % 1
		return BigInt::zero();
	}

	if exp.is_zero() { // n^0 % m
		return BigInt::one();
	}

	if base.is_zero() { // 0^n % m, n>0
		return BigInt::zero();
	}

	let mut result = BigInt::one();
	base = base % &modulus;

	// fast path for base divisible by modulus.
	if base.is_zero() { return BigInt::zero() }
	while !exp.is_zero() {
		if exp.is_odd() {
			result = (result * &base) % &modulus;
		}

		exp = exp >> 1;
		base = (base.clone() * base) % &modulus;
	}
	result
}

#[no_mangle]
pub extern fn rust_bignum_operation(op: c_int, _opt: c_int) -> c_int {
    let num2 = NUM2.lock().unwrap().clone();
    let num3 = NUM3.lock().unwrap().clone();
    let num4 = NUM4.lock().unwrap().clone();

    let mut ret = -1;
    match op {
        1 => { /* BN_FUZZ_OP_ADD = 1 */
            *(NUM1.lock().unwrap()) = num2.add(num3).clone();
            ret = 0;
        }
        2 => { /* BN_FUZZ_OP_SUB = 2 */
            *(NUM1.lock().unwrap()) = num2.sub(num3).clone();
            ret = 0;
        }
        3 => { /* BN_FUZZ_OP_SUB = 3 */
            *(NUM1.lock().unwrap()) = num2.mul(num3).clone();
            ret = 0;
        }
        4 => { /* BN_FUZZ_OP_DIV = 4 */
            if num3 > BigInt::zero() {
                *(NUM1.lock().unwrap()) = num2.div(num3).clone();
                ret = 0;
            } else {
                ret = -1;
            }
        }
        5 => { /* BN_FUZZ_OP_MOD = 5 */
            if num2 >= BigInt::zero() && num3 > BigInt::zero()  {
                *(NUM1.lock().unwrap()) = num2.rem(num3).clone();
                ret = 0;
            } else {
                ret = -1
            }
        }
        6 => { /* BN_FUZZ_OP_EXP_MOD = 6 */
            if num2 > BigInt::zero() && num3 >= BigInt::zero() && num4 > BigInt::zero() {
                *(NUM1.lock().unwrap()) = modexp(num2, num3, num4);
                ret = 0;
            } else {
                ret = -1
            }
        }
        7 => { /* BN_FUZZ_OP_LSHIFT = 7 */
            *(NUM1.lock().unwrap()) = num2.shl(1).clone();
            ret = 0;
        }
        8 => { /* BN_FUZZ_OP_RSHIFT = 8 * */
            *(NUM1.lock().unwrap()) = num2.shr(1).clone();
            ret = 0;
        }
        9 => { /* BN_FUZZ_OP_GCD = 9 */
            if num2 > BigInt::zero() && num3 > BigInt::zero() {
                *(NUM1.lock().unwrap()) = num2.gcd(&num3).clone();
                ret = 0;
            } else {
                ret = -1
            }
        }
        10 => { /* BN_FUZZ_OP_MOD_ADD = 10 */
            if num4 > BigInt::zero() {
                *(NUM1.lock().unwrap()) = num2.add(num3).rem(num4).clone();
                ret = 0;
            } else {
                ret = -1
            }
        }
        11 => { /* BN_FUZZ_OP_EXP = 11 */
            if num2 > BigInt::zero() && num2 <= BigInt::from_str_radix("1000", 10).unwrap() && num3 <= BigInt::from_str_radix("1000", 10).unwrap() && num3 > BigInt::zero() {
                let exp = num3.to_usize().unwrap();
                *(NUM1.lock().unwrap()) = pow(num2, exp);

            } else {
                ret = -1
            }
        }
        12 => { /* BN_FUZZ_OP_CMP = 12 */
            if num2 > num3 {
                *(NUM1.lock().unwrap()) = BigInt::one();
            } else if num2 == num3 {
                *(NUM1.lock().unwrap()) = BigInt::zero();
            } else {
                *(NUM1.lock().unwrap()) = BigInt::from_str_radix("-1", 10).unwrap();
            }
            ret = 0;
        }
        13 => { /* BN_FUZZ_OP_SQR = 13 */
            *(NUM1.lock().unwrap()) = pow(num2, 2);
            ret = 0;
        }
        14 => { /* BN_FUZZ_OP_NEG = 14 */
            *(NUM1.lock().unwrap()) = num2.neg().clone();
            ret = 0;
        }
        15 => { /* BN_FUZZ_OP_ABS = 15 */
            *(NUM1.lock().unwrap()) = num2.abs().clone();
            ret = 0;
        }
        17 => { /* BN_FUZZ_OP_MOD_SUB = 17 */
            if num4 > BigInt::zero() {
                //*(NUM1.lock().unwrap()) = num3.sub(num2).rem(num4).clone();
                *(NUM1.lock().unwrap()) = num2.sub(num3).rem(num4).clone();
                ret = 0;
            } else {
                ret = -1
            }
        }
        _ => {
            ret = -1;
        }
    }
    return ret;
}

#[no_mangle]
pub extern fn rust_bignum_shutdown() {
}
