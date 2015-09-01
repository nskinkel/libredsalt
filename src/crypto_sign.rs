use ffi;

#[derive(Debug)]
pub enum CryptoSignErr {
    InvalidSKLengthErr,
    KeyGenErr,
    SignErr,
}

/// Generate a signing keypair.
///
/// The ```crypto_sign_keypair()``` function randomly generates a secret key
/// and a corresponding public key. It puts the secret key into ```sk``` and
/// returns the public key. It guarantees that ```sk``` has
/// ```crypto_sign_SECRETKEYBYTES``` bytes and that ```pk``` has
/// ```crypto_sign_PUBLICKEYBYTES``` bytes.
///
/// # Failures
/// If ```sk``` is not ```crypto_sign_SECRETKEYBYTES``` long, a
/// ```CryptoSignErr::InvalidSKLengthErr``` will be returned. If the internal
/// key generation process fails, ```CryptoSignErr::KeyGenErr``` will be
/// returned.
///
/// # Examples
///
/// Generating a signing keypair:
///
/// ```
/// let mut sk = [0 as u8; crypto_sign_SECRETKEYBYTES];
/// let mut pk = try!(crypto_sign_keypair(sk));
/// ```
///
pub fn crypto_sign_keypair(sk: &mut[u8]) -> Result<Box<[u8]>, CryptoSignErr> {
    if sk.len() != ffi::crypto_sign_SECRETKEYBYTES {
        return Err(CryptoSignErr::InvalidSKLengthErr);
    }

    let mut pk = Box::new([0 as u8; ffi::crypto_sign_PUBLICKEYBYTES]);

    unsafe {
        match ffi::crypto_sign_ed25519_tweet_keypair(pk.as_mut_ptr(),
                                                     sk.as_mut_ptr()) {
            0 => Ok(pk),
            _ => Err(CryptoSignErr::KeyGenErr),
        }
    }
}

pub fn crypto_sign(m: &[u8], sk: &[u8]) -> Result<Box<[u8]>, CryptoSignErr> {
    if sk.len() != ffi::crypto_sign_SECRETKEYBYTES {
        return Err(CryptoSignErr::InvalidSKLengthErr);
    }

    let mlen = m.len();
    let mut sm: Box<[u8]> = Vec::with_capacity(mlen+ffi::crypto_sign_BYTES)
                                 .into_boxed_slice();
    let smlen: u64 = 0;

    unsafe {
        match ffi::crypto_sign_ed25519_tweet(sm.as_mut_ptr(),
                                             smlen as *mut u64,
                                             m.as_ptr(),
                                             mlen as u64,
                                             sk.as_ptr()) {
            0 => Ok(sm),
            _ => Err(CryptoSignErr::SignErr),
        }
    }
}

/*
pub fn crypto_sign_open(m: &mut[u8], mlen: &mut u64, sm: &[u8], n: u64,
                        pk: &[u8]) {
    unsafe {
        ffi::crypto_sign_ed25519_tweet_open(
            m.as_mut_ptr(), mlen, sm.as_ptr(), n, pk.as_ptr()
        );
    }
}
*/
