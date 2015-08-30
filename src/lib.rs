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

pub fn crypto_box_beforenm() {
    unsafe {
        //ffi::crypto_box_beforenm();
    }
}

pub fn crypto_box_afternm() {
    unsafe {
        //ffi::crypto_box_afternm();
    }
}

pub fn crypto_box_open_afternm() {
    unsafe {
        //ffi::crypto_box_open_afternm();
    }
}

pub fn crypto_box() {
    unsafe {
        //ffi::crypto_box();
    }
}

pub fn crypto_box_open() {
    unsafe {
        //ffi::crypto_box_open();
    }
}

pub fn crypto_secretbox() {
    unsafe {
        //ffi::crypto_secretbox();
    }
}

pub fn crypto_secretbox_open() {
    unsafe {
        //ffi::crypto_secretbox_open();
    }
}

pub fn crypto_hash() {
    unsafe {
        //ffi::crypto_hash();
    }
}

pub fn crypto_sign_keypair() {
    unsafe {
        //ffi::crypto_sign_keypair();
    }
}

pub fn crypto_sign() {
    unsafe {
        //ffi::crypto_sign();
    }
}

pub fn crypto_sign_open() {
    unsafe {
        //ffi::crypto_sign_open();
    }
}
