use ffi;

pub const PUBLICKEYBYTES:   usize = 32;
pub const SECRETKEYBYTES:   usize = 64;
pub const BYTES:            usize = 64;

#[derive(Debug, Eq, PartialEq)]
pub enum Error {
    Length,
    Verify,
}

/// Generate a signing keypair.
///
/// The `crypto_sign_keypair()` function randomly generates a secret key
/// and a corresponding public key. It puts the secret key into `sk` and
/// returns the public key. It guarantees that `sk` has
/// `crypto_sign::SECRETKEYBYTES` bytes and that `pk` has
/// `crypto_sign::PUBLICKEYBYTES` bytes.
///
/// # Examples
///
/// Generate a signing keypair:
///
/// ```
/// let mut sk = [0 as u8; crypto_sign::SECRETKEYBYTES];
/// let pk = crypto_sign_keypair(&sk);
/// ```
pub fn crypto_sign_keypair(sk: &mut[u8; SECRETKEYBYTES])
-> [u8; PUBLICKEYBYTES] {

    let mut pk = [0 as u8; PUBLICKEYBYTES];

    unsafe {
        match ffi::crypto_sign_ed25519_tweet_keypair(pk.as_mut_ptr(),
                                                     sk.as_mut_ptr()) {
            0 => pk,
            _ => unreachable!("Internal error."),
        }
    }
}

/// Sign a message.
///
/// The `crypto_sign()` function signs a message `m` using the signer's secret
/// key `sk`. The `crypto_sign()` function returns the resulting signed message
/// `sm`.
///
/// # Examples
///
/// Sign a message:
///
/// ```
/// let sm = crypto_sign(&m, &sk);
/// ```
pub fn crypto_sign(m: &[u8], sk: &[u8; SECRETKEYBYTES]) -> Vec<u8> {

    let mlen = m.len();
    let mut sm = vec![0 as u8; mlen+BYTES];
    let mut smlen: u64 = 0;

    unsafe {
        match ffi::crypto_sign_ed25519_tweet(sm.as_mut_ptr(),
                                             &mut smlen as *mut u64,
                                             m.as_ptr(),
                                             mlen as u64,
                                             sk.as_ptr()) {
            0 => sm,
            _ => unreachable!("Internal error."),
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
/// If the signature fails verification, `Error::Verify` is returned.
/// `Error::Length` is returned if `sm` is too short to be a valid signed
/// message (less than `crypto_sign::BYTES+1` bytes long).
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
pub fn crypto_sign_open(sm: &[u8], pk: &[u8; PUBLICKEYBYTES])
-> Result<Vec<u8>, Error> {

    let smlen = sm.len();

    if smlen <= BYTES {
        return Err(Error::Length);
    }

    let mut mlen: u64 = (smlen-BYTES) as u64;
    let mut m = vec![0 as u8; mlen as usize];

    unsafe {
        match ffi::crypto_sign_ed25519_tweet_open(m.as_mut_ptr(),
                                                  &mut mlen as *mut u64,
                                                  sm.as_ptr(),
                                                  smlen as u64,
                                                  pk.as_ptr()) {
            0  => Ok(m),
            -1 => Err(Error::Verify),
            _  => unreachable!("Internal error."),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crypto_sign_keypair_ok() {
        let mut sk = [0 as u8; SECRETKEYBYTES];
        let pk = crypto_sign_keypair(&mut sk);
        assert_eq!(pk.len(), PUBLICKEYBYTES);
    }

    #[test]
    fn crypto_sign_ok() {
        let sk = [0 as u8; SECRETKEYBYTES];
        let m = [1 as u8, 2, 3, 4, 5];
        let sm = crypto_sign(&m, &sk);
        assert_eq!(sm.len(), 5+BYTES);
        assert_eq!(&sm[BYTES..BYTES+5], m);
    }

    #[test]
    fn crypto_sign_open_ok() {
        // create a valid keypair
        let mut sk = [0 as u8; SECRETKEYBYTES];
        let pk = crypto_sign_keypair(&mut sk);
        // sign a test message
        let m = [1 as u8, 2, 3, 4, 5];
        let sm = crypto_sign(&m, &sk);
        // verify the signature
        let opened_m = match crypto_sign_open(&sm, &pk) {
            Ok(v) => v,
            Err(e) => panic!(e),
        };
        assert_eq!(opened_m, m);
    }

    #[test]
    fn crypto_sign_open_invalid_message_len() {
        let pk = [0 as u8; PUBLICKEYBYTES];
        let result = crypto_sign_open(&[0 as u8; BYTES], &pk);
        assert!(result == Err(Error::Length));
    }

    #[test]
    fn crypto_sign_open_verification_fail() {
        // create a valid keypair
        let mut sk = [0 as u8; SECRETKEYBYTES];
        let pk = crypto_sign_keypair(&mut sk);
        // sign a test message
        let m = [1 as u8, 2, 3, 4, 5];
        let sm = crypto_sign(&m, &sk);

        let mut invalid_pk = pk.clone();
        let mut invalid_sig = sm.clone();
        let mut invalid_msg = sm.clone();

        // modify the signature
        invalid_sig[0] = sm[0] ^ 1;
        // modify the message
        invalid_msg[BYTES+1] = invalid_msg[BYTES+1] ^ 1;
        // modify the pk
        invalid_pk[0] = invalid_pk[0] ^ 1;

        // attempt verification
        let result = crypto_sign_open(&invalid_sig, &pk);
        assert!(result == Err(Error::Verify));

        let result = crypto_sign_open(&invalid_msg, &pk);
        assert!(result == Err(Error::Verify));

        let result = crypto_sign_open(&sm, &invalid_pk);
        assert!(result == Err(Error::Verify));
    }
}
