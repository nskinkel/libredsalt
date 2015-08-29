#![allow(non_upper_case_globals)]
#![allow(dead_code)]  // TODO: Remove this later.

use libc::{size_t, c_int};

pub const crypto_box_PUBLICKEYBYTES: i32 = 32;
pub const crypto_box_SECRETKEYBYTES: i32 = 32;
pub const crypto_box_NONCEBYTES: i32 = 24;
pub const crypto_box_ZEROBYTES: i32 = 32;
pub const crypto_box_BOXZEROBYTES: i32 = 16;
pub const crypto_box_BEFORENMBYTES: i32 = 32;

#[link(name = "tweetnacl", kind = "static")]
extern {
    //fn crypto_box_open(source_length: size_t) -> size_t;
    //fn crypto_box_open(u8 *m, const u8 *c, u64 d, const u8 *n,const u8 *y,const u8 *x) -> c_int;
    pub fn crypto_box_keypair(pk: *mut u8, sk: *mut u8) -> i32;
}
