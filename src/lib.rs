extern crate libc;
extern crate rand;

mod ffi;

pub mod randombytes;
pub mod crypto_sign;

/// Returns true iff the two 16 byte strings are equivalent.
///
/// ```
/// let x: [42u8; 16];
/// let y: [42u8; 16];
/// assert!(crypto_verify_16(x, y) == true);
/// ```
pub fn crypto_verify_16(x: &[u8], y: &[u8]) -> bool {
    assert!(x.len() == 16, "`x` must be 16 bytes.");
    assert!(y.len() == 16, "`y` must be 16 bytes.");
    unsafe {
        match ffi::crypto_verify_16_tweet(x.as_ptr(), y.as_ptr()) {
            0 => true,
            -1 => false,
            _ => unreachable!("Unexpected value produced by `crypto_verify_16_tweet()`.")
        }
    }
}

/// Returns true iff the two 32 byte strings are equivalent.
/// ```
/// let x: [42u8; 32];
/// let y: [42u8; 32];
/// assert!(crypto_verify_32(x, y) == true);
/// ```
pub fn crypto_verify_32(x: &[u8], y: &[u8]) -> bool {
    assert!(x.len() == 32, "`x` must be 32 bytes.");
    assert!(y.len() == 32, "`y` must be 32 bytes.");
    unsafe {
        match ffi::crypto_verify_32_tweet(x.as_ptr(), y.as_ptr()) {
            0 => true,
            -1 => false,
            _ => unreachable!("Unexpected value produced by `crypto_verify_32_tweet()`.")
        }
    }
}

pub fn crypto_stream(out: &mut[u8], d: u64, n: &[u8], k: &[u8]) {
    unsafe {
        ffi::crypto_stream_xsalsa20_tweet(out.as_mut_ptr(), d, n.as_ptr(), k.as_ptr());
    }
}

pub fn crypto_stream_xor(c: &mut[u8], m: &[u8], d: u64, n: &[u8], k: &[u8]) {
    unsafe {
        ffi::crypto_stream_xsalsa20_tweet_xor(c.as_mut_ptr(), m.as_ptr(), d, n.as_ptr(), k.as_ptr());
    }
}

pub fn crypto_onetimeauth(out: &mut[u8], m: &[u8], n: u64, k: &[u8]) {
    unsafe {
        ffi::crypto_onetimeauth_poly1305_tweet(out.as_mut_ptr(), m.as_ptr(), n, k.as_ptr());
    }
}

pub fn crypto_onetimeauth_verify(h: &[u8], m: &[u8], n: u64, k: &[u8]) {
    unsafe {
        ffi::crypto_onetimeauth_poly1305_tweet_verify(h.as_ptr(), m.as_ptr(), n, k.as_ptr());
    }
}

pub fn crypto_scalarmult(q: &mut[u8], n: &[u8], p: &[u8]) {
    unsafe {
        ffi::crypto_scalarmult_curve25519_tweet(q.as_mut_ptr(), n.as_ptr(), p.as_ptr());
    }
}

pub fn crypto_scalarmult_base(q: &mut[u8], n: &[u8]) {
    unsafe {
        ffi::crypto_scalarmult_curve25519_tweet_base(q.as_mut_ptr(), n.as_ptr());
    }
}


#[test]
fn test_crypto_box_keypair() {
    let mut pk = [0u8; ffi::crypto_box_PUBLICKEYBYTES];
    let mut sk = [0u8; ffi::crypto_box_SECRETKEYBYTES];
    println!("rv: {:?}", crypto_box_keypair(&mut pk, &mut sk));
    println!("pk: {:?}", pk);
    println!("sk: {:?}", sk);
}

pub fn crypto_box_keypair(pk: &mut[u8], sk: &mut[u8]) -> i32 {
    // TODO: Assert correctly sized slices.
    unsafe {
        ffi::crypto_box_curve25519xsalsa20poly1305_tweet_keypair(pk.as_mut_ptr(), sk.as_mut_ptr())
    }
}

pub fn crypto_box_beforenm(k: &mut[u8], y: &[u8], x: &[u8]) {
    unsafe {
        ffi::crypto_box_curve25519xsalsa20poly1305_tweet_beforenm(
            k.as_mut_ptr(), y.as_ptr(), x.as_ptr()
        );
    }
}

pub fn crypto_box_afternm(c: &mut[u8], m: &[u8], d: u64, n: &[u8],
                          k: &[u8]) {
    unsafe {
        ffi::crypto_box_curve25519xsalsa20poly1305_tweet_afternm(
            c.as_mut_ptr(), m.as_ptr(), d, n.as_ptr(), k.as_ptr()
        );
    }
}

pub fn crypto_box_open_afternm(m: &mut[u8], c: &[u8], d: u64, n: &[u8],
                               k: &[u8]) {
    unsafe {
        ffi::crypto_box_curve25519xsalsa20poly1305_tweet_open_afternm(
            m.as_mut_ptr(), c.as_ptr(), d, n.as_ptr(), k.as_ptr()
        );
    }
}

pub fn crypto_box(c: &mut[u8], m: &[u8], d: u64, n: &[u8], y: &[u8],
                  x: &[u8]) {
    unsafe {
        ffi::crypto_box_curve25519xsalsa20poly1305_tweet(
            c.as_mut_ptr(), m.as_ptr(), d, n.as_ptr(), y.as_ptr(), x.as_ptr()
        );
    }
}

pub fn crypto_box_open(m: &mut[u8], c: &[u8], d: u64, n: &[u8], y: &[u8],
                       x: &[u8]) {
    unsafe {
        ffi::crypto_box_curve25519xsalsa20poly1305_tweet_open(
            m.as_mut_ptr(), c.as_ptr(), d, n.as_ptr(), y.as_ptr(), x.as_ptr()
        );
    }
}

pub fn crypto_secretbox(c: &mut[u8], m: &[u8], d: u64, n: &[u8], k: &[u8]) {
    unsafe {
        ffi::crypto_secretbox_xsalsa20poly1305_tweet(
            c.as_mut_ptr(), m.as_ptr(), d, n.as_ptr(), k.as_ptr()
        );
    }
}

pub fn crypto_secretbox_open(m: &mut[u8], c: &[u8], d: u64, n: &[u8],
                             k: &[u8]) {
    unsafe {
        ffi::crypto_secretbox_xsalsa20poly1305_tweet_open(
            m.as_mut_ptr(), c.as_ptr(), d, n.as_ptr(), k.as_ptr()
        );
    }
}

pub fn crypto_hash(out: &mut[u8], m: &[u8], n: u64) {
    unsafe {
        ffi::crypto_hash_sha512_tweet(
            out.as_mut_ptr(), m.as_ptr(), n
        );
    }
}
