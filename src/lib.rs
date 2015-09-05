extern crate libc;
extern crate rand;

mod ffi;

pub mod crypto_box;
pub mod randombytes;

pub fn crypto_verify_16(x: &[u8], y: &[u8]) {
    unsafe {
        ffi::crypto_verify_16_tweet(x.as_ptr(), y.as_ptr());
    }
}

pub fn crypto_verify_32_tweet(x: &[u8], y: &[u8]) {
    unsafe {
        ffi::crypto_verify_32_tweet(x.as_ptr(), y.as_ptr());
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

pub fn crypto_sign_keypair(pk: &mut[u8], sk: &mut[u8]) {
    unsafe {
        ffi::crypto_sign_ed25519_tweet_keypair(
            pk.as_mut_ptr(), sk.as_mut_ptr()
        );
    }
}

pub fn crypto_sign(sm: &mut[u8], smlen: &mut u64, m: &[u8], n: u64,
                   sk: &[u8]) {
    unsafe {
        ffi::crypto_sign_ed25519_tweet(
            sm.as_mut_ptr(), smlen, m.as_ptr(), n, sk.as_ptr()
        );
    }
}

pub fn crypto_sign_open(m: &mut[u8], mlen: &mut u64, sm: &[u8], n: u64,
                        pk: &[u8]) {
    unsafe {
        ffi::crypto_sign_ed25519_tweet_open(
            m.as_mut_ptr(), mlen, sm.as_ptr(), n, pk.as_ptr()
        );
    }
}
