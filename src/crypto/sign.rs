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
/// The `keypair()` function randomly generates a secret key
/// and a corresponding public key. It puts the secret key into `sk` and
/// returns the public key. It guarantees that `sk` has
/// `crypto::sign::SECRETKEYBYTES` bytes and that `pk` has
/// `crypto::sign::PUBLICKEYBYTES` bytes.
///
/// # Examples
///
/// Generate a signing keypair:
///
/// ```
/// # use tweetnaclrs::crypto::sign;
/// let mut sk = [0 as u8; sign::SECRETKEYBYTES];
/// let pk = sign::keypair(&mut sk);
/// ```
pub fn keypair(sk: &mut[u8; SECRETKEYBYTES]) -> [u8; PUBLICKEYBYTES] {

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
/// The `sign()` function signs a message `m` using the signer's secret
/// key `sk`. The `sign()` function returns the resulting signed message `sm`.
///
/// # Examples
///
/// Sign a message `m` using a secret key `sk`:
///
/// ```
/// # use tweetnaclrs::crypto::sign;
/// # let sk = [0 as u8; 64];
/// let m = b"I accept your offer.";
/// let sm = sign::sign(m, &sk);
/// ```
pub fn sign(m: &[u8], sk: &[u8; SECRETKEYBYTES]) -> Vec<u8> {

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
/// The `open()` function verifies the signature in `sm` using the
/// signer's public key `pk`. The `open()` function returns the
/// message `m`.
///
/// # Failures
///
/// If the signature fails verification, `Error::Verify` is returned.
/// `Error::Length` is returned if `sm` is too short to be a valid signed
/// message (less than `crypto::sign::BYTES+1` bytes long).
///
/// # Examples
///
/// Verify the signature of message `sm` with public key `pk`:
///
/// ```should_panic
/// # use tweetnaclrs::crypto::sign;
/// # let sm = [0 as u8; 65];
/// # let pk = [1 as u8; 32];
/// let m = sign::open(&sm, &pk)
///                 .ok()
///                 .expect("Signature verification failed!");
/// ```
pub fn open(sm: &[u8], pk: &[u8; PUBLICKEYBYTES]) -> Result<Vec<u8>, Error> {

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
    fn keypair_ok() {
        let mut sk = [0 as u8; SECRETKEYBYTES];
        let pk = keypair(&mut sk);
        assert_eq!(pk.len(), PUBLICKEYBYTES);
    }

    #[test]
    fn sign_ok() {
        let sk = [0 as u8; SECRETKEYBYTES];
        let m = [1 as u8, 2, 3, 4, 5];
        let sm = sign(&m, &sk);
        assert_eq!(sm.len(), 5+BYTES);
        assert_eq!(&sm[BYTES..BYTES+5], m);
    }

    #[test]
    fn open_ok() {
        // create a valid keypair
        let mut sk = [0 as u8; SECRETKEYBYTES];
        let pk = keypair(&mut sk);
        // sign a test message
        let m = [1 as u8, 2, 3, 4, 5];
        let sm = sign(&m, &sk);
        // verify the signature
        let opened_m = match open(&sm, &pk) {
            Ok(v) => v,
            Err(e) => panic!(e),
        };
        assert_eq!(opened_m, m);
    }

    #[test]
    fn open_invalid_message_len() {
        let pk = [0 as u8; PUBLICKEYBYTES];
        let result = open(&[0 as u8; BYTES], &pk);
        assert!(result == Err(Error::Length));
    }

    #[test]
    fn open_verification_fail() {
        // create a valid keypair
        let mut sk = [0 as u8; SECRETKEYBYTES];
        let pk = keypair(&mut sk);
        // sign a test message
        let m = [1 as u8, 2, 3, 4, 5];
        let sm = sign(&m, &sk);

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
        let result = open(&invalid_sig, &pk);
        assert!(result == Err(Error::Verify));

        let result = open(&invalid_msg, &pk);
        assert!(result == Err(Error::Verify));

        let result = open(&sm, &invalid_pk);
        assert!(result == Err(Error::Verify));
    }
}
