use ffi;

#[derive(Debug, Eq, PartialEq)]
pub enum CryptoSignErr {
    KeyGen,
    Sign,
    SignedMessageLength,
    SignatureVerification,
}

/// Generate a signing keypair.
///
/// The `crypto_sign_keypair()` function randomly generates a secret key
/// and a corresponding public key. It puts the secret key into `sk` and
/// returns the public key. It guarantees that `sk` has
/// `crypto_sign_SECRETKEYBYTES` bytes and that `pk` has
/// `crypto_sign_PUBLICKEYBYTES` bytes.
///
/// # Failures
///
/// If the internal key generation process fails,
/// `Err(CryptoSignErr::KeyGen)` will be returned.
///
/// # Examples
///
/// Generating a signing keypair:
///
/// ```
/// let mut sk = [0 as u8; crypto_sign_SECRETKEYBYTES];
/// let pk = crypto_sign_keypair(sk).ok().expect("Key generation failed!");
/// ```
pub fn crypto_sign_keypair(sk: &mut[u8; ffi::crypto_sign_SECRETKEYBYTES])
    -> Result<[u8; ffi::crypto_sign_PUBLICKEYBYTES], CryptoSignErr> {

    let mut pk = [0 as u8; ffi::crypto_sign_PUBLICKEYBYTES];

    unsafe {
        match ffi::crypto_sign_ed25519_tweet_keypair(pk.as_mut_ptr(),
                                                     sk.as_mut_ptr()) {
            0 => Ok(pk),
            _ => Err(CryptoSignErr::KeyGen),
        }
    }
}

/// Sign a message.
///
/// The `crypto_sign()` function signs a message `m` using the signer's secret
/// key `sk`. The `crypto_sign()` function returns the resulting signed message
/// `sm`.
///
/// # Failures
///
/// The function returns `CryptoSignErr::Sign` if an internal error occurs
/// during the sign operation.
///
/// # Examples
///
/// Signing a message:
///
/// ```
/// let sm = crypto_sign(&m, &sk).ok().expect("Signature failed!");
/// ```
pub fn crypto_sign(m: &[u8], sk: &[u8; ffi::crypto_sign_SECRETKEYBYTES])
    -> Result<Vec<u8>, CryptoSignErr> {

    let mlen = m.len();
    let mut sm = vec![0 as u8; mlen+ffi::crypto_sign_BYTES];
    let mut smlen: u64 = 0;

    unsafe {
        match ffi::crypto_sign_ed25519_tweet(sm.as_mut_ptr(),
                                             &mut smlen as *mut u64,
                                             m.as_ptr(),
                                             mlen as u64,
                                             sk.as_ptr()) {
            0 => Ok(sm),
            _ => Err(CryptoSignErr::Sign),
        }
    }
}

/// Verify a message signature.
///
/// The `crypto_sign_open()` function verifies the signature in `sm` using the
/// signer's public key `pk`. The `crypto_sign_open()` function returns the
/// message `m`.
///
/// # Failures
///
/// If the signature fails verification, `CryptoSignErr::SignatureVerification`
/// is returned. `CryptoSignErr::SignedMessageLength` is returned if `sm` is
/// too short to be a valid signed message (less than `crypto_sign_BYTES+1`
/// bytes long).
///
/// # Examples
///
/// Verify a message signature:
///
/// ```
/// let m = crypto_sign_open(&sm, &pk)
///             .ok()
///             .expect("Signature verification failed!");
/// ```
pub fn crypto_sign_open(sm: &[u8], pk: &[u8; ffi::crypto_sign_PUBLICKEYBYTES])
                        -> Result<Vec<u8>, CryptoSignErr> {

    let smlen = sm.len();

    if smlen <= ffi::crypto_sign_BYTES {
        return Err(CryptoSignErr::SignedMessageLength);
    }

    let mut mlen: u64 = (smlen-ffi::crypto_sign_BYTES) as u64;
    let mut m = vec![0 as u8; mlen as usize];

    unsafe {
        match ffi::crypto_sign_ed25519_tweet_open(m.as_mut_ptr(),
                                                  &mut mlen as *mut u64,
                                                  sm.as_ptr(),
                                                  smlen as u64,
                                                  pk.as_ptr()) {
            0 => Ok(m),
            _ => Err(CryptoSignErr::SignatureVerification),
        }
    }
}

#[cfg(test)]
mod tests {
    use ffi;
    use super::*;

    #[test]
    fn crypto_sign_keypair_ok() {
        let mut sk = [0 as u8; ffi::crypto_sign_SECRETKEYBYTES];
        let pk = match crypto_sign_keypair(&mut sk) {
            Ok(v) => v,
            Err(e) => panic!(e),
        };
        assert_eq!(pk.len(), ffi::crypto_sign_PUBLICKEYBYTES);
    }

    #[test]
    fn crypto_sign_ok() {
        let sk = [0 as u8; ffi::crypto_sign_SECRETKEYBYTES];
        let m = [1 as u8, 2, 3, 4, 5];
        let sm = match crypto_sign(&m, &sk) {
            Ok(v) => v,
            Err(e) => panic!(e),
        };
        assert_eq!(sm.len(), 5+ffi::crypto_sign_BYTES);
        assert_eq!(&sm[ffi::crypto_sign_BYTES .. ffi::crypto_sign_BYTES+5], m);
    }

    #[test]
    fn crypto_sign_open_ok() {
        // create a valid keypair
        let mut sk = [0 as u8; ffi::crypto_sign_SECRETKEYBYTES];
        let pk = match crypto_sign_keypair(&mut sk) {
            Ok(v) => v,
            Err(e) => panic!(e),
        };
        // sign a test message
        let m = [1 as u8, 2, 3, 4, 5];
        let sm = match crypto_sign(&m, &sk) {
            Ok(v) => v,
            Err(e) => panic!(e),
        };
        // verify the signature
        let opened_m = match crypto_sign_open(&sm, &pk) {
            Ok(v) => v,
            Err(e) => panic!(e),
        };
        assert_eq!(opened_m, m);
    }

    #[test]
    fn crypto_sign_open_invalid_message_len() {
        let pk = [0 as u8; ffi::crypto_sign_PUBLICKEYBYTES];
        let result = crypto_sign_open(&[0 as u8; ffi::crypto_sign_BYTES],
                                      &pk);
        assert!(result == Err(CryptoSignErr::SignedMessageLength));
    }

    #[test]
    fn crypto_sign_open_verification_fail() {
        // create a valid keypair
        let mut sk = [0 as u8; ffi::crypto_sign_SECRETKEYBYTES];
        let pk = match crypto_sign_keypair(&mut sk) {
            Ok(v) => v,
            Err(e) => panic!(e),
        };
        // sign a test message
        let m = [1 as u8, 2, 3, 4, 5];
        let sm = match crypto_sign(&m, &sk) {
            Ok(v) => v,
            Err(e) => panic!(e),
        };

        let mut invalid_pk = pk.clone();
        let mut invalid_sig = sm.clone();
        let mut invalid_msg = sm.clone();

        // modify the signature
        invalid_sig[0] = sm[0] ^ sm[0];
        // modify the message
        invalid_msg[ffi::crypto_sign_BYTES+1] =
            invalid_msg[ffi::crypto_sign_BYTES+1] ^
            invalid_msg[ffi::crypto_sign_BYTES+1];
        // modify the pk
        invalid_pk[0] = invalid_pk[0] ^ invalid_pk[0];

        // attempt verification
        let result = crypto_sign_open(&invalid_sig, &pk);
        assert!(result == Err(CryptoSignErr::SignatureVerification));

        let result = crypto_sign_open(&invalid_msg, &pk);
        assert!(result == Err(CryptoSignErr::SignatureVerification));

        let result = crypto_sign_open(&sm, &invalid_pk);
        assert!(result == Err(CryptoSignErr::SignatureVerification));
    }
}
