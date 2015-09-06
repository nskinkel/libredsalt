#![allow(non_upper_case_globals)]
#![allow(dead_code)]  // TODO: Remove this later.

use libc::{c_int};

pub const crypto_auth_BYTES: usize = 32;
pub const crypto_auth_KEYBYTES: usize = 32;

pub const crypto_box_PUBLICKEYBYTES: usize = 32;
pub const crypto_box_SECRETKEYBYTES: usize = 32;
pub const crypto_box_NONCEBYTES: usize = 24;
pub const crypto_box_ZEROBYTES: usize = 32;
pub const crypto_box_BOXZEROBYTES: usize = 16;
pub const crypto_box_BEFORENMBYTES: usize = 32;

pub const crypto_hash_BYTES: usize = 64;

pub const crypto_onetimeauth_BYTES: usize = 16;
pub const crypto_onetimeauth_KEYBYTES: usize = 32;

pub const crypto_scalarmult_BYTES: usize = 32;
pub const crypto_scalarmult_SCALARBYTES: usize = 32;

pub const crypto_secretbox_KEYBYTES: usize = 32;
pub const crypto_secretbox_NONCEBYTES: usize = 24;
pub const crypto_secretbox_ZEROBYTES: usize = 32;
pub const crypto_secretbox_BOXZEROBYTES: usize = 16;

pub const crypto_sign_PUBLICKEYBYTES: usize = 32;
pub const crypto_sign_SECRETKEYBYTES: usize = 64;
pub const crypto_sign_BYTES: usize = 64;

pub const crypto_stream_KEYBYTES: usize = 32;
pub const crypto_stream_NONCEBYTES: usize = 24;


extern {
    pub fn crypto_verify_16_tweet(x: *const u8, y: *const u8) -> c_int;
    pub fn crypto_verify_32_tweet(x: *const u8, y: *const u8) -> c_int;

    pub fn crypto_stream_xsalsa20_tweet(c: *mut u8, d: u64, n: *const u8, k: *const u8) -> c_int;
    pub fn crypto_stream_xsalsa20_tweet_xor(c: *mut u8, m: *const u8, d: u64, n: *const u8, k: *const u8) -> c_int;

    pub fn crypto_onetimeauth_poly1305_tweet(out: *mut u8, m: *const u8, n: u64, k: *const u8) -> c_int;
    pub fn crypto_onetimeauth_poly1305_tweet_verify(h: *const u8, m: *const u8, n: u64, k: *const u8) -> c_int;

    pub fn crypto_scalarmult_curve25519_tweet(q: *mut u8, n: *const u8, p: *const u8) -> c_int;
    pub fn crypto_scalarmult_curve25519_tweet_base(q: *mut u8, n: *const u8) -> c_int;

    pub fn crypto_box_curve25519xsalsa20poly1305_tweet_keypair(
        pk: *mut u8, sk: *mut u8)
        -> c_int;

    pub fn crypto_box_curve25519xsalsa20poly1305_tweet_beforenm(
        k: *mut u8, y: *const u8, x: *const u8)
        -> c_int;

    pub fn crypto_box_curve25519xsalsa20poly1305_tweet_afternm(
        c: *mut u8, m: *const u8, d: u64, n: *const u8, k: *const u8)
        -> c_int;

    pub fn crypto_box_curve25519xsalsa20poly1305_tweet_open_afternm(
        m: *mut u8, c: *const u8, d: u64, n: *const u8, k: *const u8)
        -> c_int;

    pub fn crypto_box_curve25519xsalsa20poly1305_tweet(
        c: *mut u8, m: *const u8, d: u64, n: *const u8, y: *const u8,
        x: *const u8)
        -> c_int;

    pub fn crypto_box_curve25519xsalsa20poly1305_tweet_open(
        m: *mut u8, c: *const u8, d: u64, n: *const u8, y: *const u8,
        x: *const u8)
        -> c_int;

    pub fn crypto_secretbox_xsalsa20poly1305_tweet(
        c: *mut u8, m: *const u8, d: u64, n: *const u8, k: *const u8)
        -> c_int;

    pub fn crypto_secretbox_xsalsa20poly1305_tweet_open(
        m: *mut u8, c: *const u8, d: u64, n: *const u8, k: *const u8)
        -> c_int;

    pub fn crypto_hash_sha512_tweet(
        out: *mut u8, m: *const u8, n: u64)
        -> c_int;

    pub fn crypto_sign_ed25519_tweet_keypair(
        pk: *mut u8, sk: *mut u8)
        -> c_int;

    pub fn crypto_sign_ed25519_tweet(
        sm: *mut u8, smlen: *mut u64, m: *const u8, n: u64, sk: *const u8)
        -> c_int;

    pub fn crypto_sign_ed25519_tweet_open(
        m: *mut u8, mlen: *mut u64, sm: *const u8, n: u64,
        pk: *const u8) -> c_int;
}
