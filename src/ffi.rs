#![allow(non_upper_case_globals)]
#![allow(dead_code)]  // TODO: Remove this later.

use libc::{size_t, c_int};

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
    /*
    pub fn crypto_verify_16_tweet(const u8 *x,const u8 *y) -> c_int;
    pub fn crypto_verify_32_tweet(const u8 *x,const u8 *y) -> c_int;

    pub fn crypto_stream_xsalsa20_tweet(u8 *c,u64 d,const u8 *n,const u8 *k);
    pub fn crypto_stream_xsalsa20_tweet_xor(c,m,mlen,n,k);

    pub fn crypto_onetimeauth_poly1305_tweet(u8 *out,const u8 *m,u64 n,const u8 *k) -> c_int;
    pub fn crypto_onetimeauth_poly1305_tweet_verify(const u8 *h,const u8 *m,u64 n,const u8 *k) -> c_int;

    pub fn crypto_scalarmult_curve25519_tweet(u8 *q,const u8 *n,const u8 *p) -> c_int;
    pub fn crypto_scalarmult_curve25519_tweet_base(u8 *q,const u8 *n) -> c_int;
    */

    pub fn crypto_box_curve25519xsalsa20poly1305_tweet_keypair(pk: *mut u8, sk: *mut u8) -> c_int;
    /*
    pub fn crypto_box_curve25519xsalsa20poly1305_tweet_beforenm(u8 *k,const u8 *y,const u8 *x) -> c_int;
    pub fn crypto_box_curve25519xsalsa20poly1305_tweet_afternm(u8 *c,const u8 *m,u64 d,const u8 *n,const u8 *k) -> c_int;
    pub fn crypto_box_curve25519xsalsa20poly1305_tweet_open_afternm(u8 *m,const u8 *c,u64 d,const u8 *n,const u8 *k) -> c_int;
    pub fn crypto_box_curve25519xsalsa20poly1305_tweet(u8 *c,const u8 *m,u64 d,const u8 *n,const u8 *y,const u8 *x) -> c_int;
    pub fn crypto_box_curve25519xsalsa20poly1305_tweet_open(u8 *m,const u8 *c,u64 d,const u8 *n,const u8 *y,const u8 *x) -> c_int

    pub fn crypto_secretbox_xsalsa20poly1305_tweet(u8 *c,const u8 *m,u64 d,const u8 *n,const u8 *k) -> c_int;
    pub fn crypto_secretbox_xsalsa20poly1305_tweet_open(u8 *m,const u8 *c,u64 d,const u8 *n,const u8 *k) -> c_int;

    pub fn crypto_hash_sha512_tweet(u8 *out,const u8 *m,u64 n) -> c_int;

    pub fn crypto_sign_ed25519_tweet_keypair(u8 *pk, u8 *sk) -> c_int;
    pub fn crypto_sign_ed25519_tweet(u8 *sm,u64 *smlen,const u8 *m,u64 n,const u8 *sk) -> c_int;
    pub fn crypto_sign_ed25519_tweet_open(u8 *m,u64 *mlen,const u8 *sm,u64 n,const u8 *pk) -> c_int;
    */
}
