extern crate libc;

mod ffi;


pub fn crypto_verify_16() {
    unsafe {
        //ffi::crypto_verify_16()
    }
}

pub fn crypto_verify_32() {
    unsafe {
        //ffi::crypto_verify_32();
    }
}

pub fn crypto_stream() {
    unsafe {
        //ffi::crypto_steam();
    }
}

pub fn crypto_stream_xor() {
    unsafe {
        //ffi::crypto_steam_xor();
    }
}

pub fn crypto_onetimeauth() {
    unsafe {
        //ffi::crypto_onetimeauth();
    }
}

pub fn crypto_onetimeauth_verify() {
    unsafe {
        //ffi::crypto_onetimeauth_verify();
    }
}

pub fn crypto_scalarmult() {
    unsafe {
        //ffi::crypto_scalarmult();
    }
}

pub fn crypto_scalarmult_base() {
    unsafe {
        //ffi::crypto_scalarmult_base();
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
