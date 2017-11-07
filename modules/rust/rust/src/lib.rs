#![feature(libc)]
extern crate libc;
extern crate num;
use libc::{uint8_t, size_t, c_int};
use num::{Num, BigUint, Zero, One};
use std::ptr::{null};

#[no_mangle]
pub extern fn rust_bignum_initialize() {
}

#[no_mangle]
pub extern fn rust_bignum_bignum_from_string(s: *const char, bn_index: c_int) {
}

#[no_mangle]
pub extern fn rust_bignum_string_from_bignum(bn_index: c_int) {
}

#[no_mangle]
pub extern fn rust_bignum_operation(op: c_int) -> c_int {
    0
}

#[no_mangle]
pub extern fn rust_bignum_shutdown() {
}
