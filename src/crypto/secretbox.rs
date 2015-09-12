use crypto::onetimeauth;
use ffi;

pub const KEYBYTES:     usize = 32;
pub const NONCEBYTES:   usize = 24;
pub const ZEROBYTES:    usize = 32;
pub const BOXZEROBYTES: usize = 16;

#[derive(Debug, Eq, PartialEq)]
pub enum Error {
    Verify,
}

/// Encrypt and authenticate a message.
///
/// The `secretbox()` function encrypts and authenticates a message `m`
/// using a secret key `k` and a nonce `n`. The `secretbox()` function
/// returns the resulting ciphertext `c`.
///
/// # Examples
///
/// Encrypt and authenticate a message `m` using a nonce `n` and a secret key
/// `sk`:
///
/// ```
/// # use tweetnaclrs::crypto::secretbox;
/// # let n = [0 as u8; 24];
/// # let sk = [1 as u8; 32];
/// # let m = [0 as u8];
/// let ciphertext = secretbox::secretbox(&m, &n, &sk);
/// ```
pub fn secretbox(m: &[u8],
                 n: &[u8; NONCEBYTES],
                 k: &[u8; KEYBYTES])
-> Vec<u8> {

    let mut padded_m = vec![0 as u8; ZEROBYTES];
    padded_m.extend(m.iter().cloned());
    let mut c = vec![0 as u8; BOXZEROBYTES +
                              onetimeauth::BYTES +
                              m.len()];

    unsafe {
        match ffi::crypto_secretbox_xsalsa20poly1305_tweet(
                        c.as_mut_ptr(),
                        padded_m.as_ptr(),
                        padded_m.len() as u64,
                        n.as_ptr(),
                        k.as_ptr()) {
            0 => c[BOXZEROBYTES..].to_vec(),
            _ => unreachable!("Internal error."),
        }
    }
}

/// Verify and decrypt a message.
///
/// The `secretbox_open()` function verifies and decrypts a ciphertext
/// `c` using a secret key `k` and a nonce `n`. The `secretbox_open()`
/// function returns the resulting plaintext `m`.
///
/// # Failures
///
/// An `Error::Verify` is returned if the ciphertext fails verification.
///
/// # Examples
///
/// Verify and decrypt a ciphertext `c` using a nonce `n` and a secret key
/// `sk`:
///
/// ```should_panic
/// # use tweetnaclrs::crypto::secretbox;
/// # let c = [1 as u8];
/// # let n = [0 as u8; 24];
/// # let sk = [1 as u8; 32];
/// let plaintext = secretbox::open(&c, &n, &sk).ok().expect("Verification failed!");
/// ```
pub fn open(c: &[u8],
            n: &[u8; NONCEBYTES],
            k: &[u8; KEYBYTES])
-> Result<Vec<u8>, Error> {

    let mut padded_c = vec![0 as u8; BOXZEROBYTES];
    padded_c.extend(c.iter().cloned());
    let mut m = vec![0 as u8; padded_c.len()];

    unsafe {
        match ffi::crypto_secretbox_xsalsa20poly1305_tweet_open(
                        m.as_mut_ptr(),
                        padded_c.as_ptr(),
                        padded_c.len() as u64,
                        n.as_ptr(),
                        k.as_ptr()) {
            0  => Ok(m[ZEROBYTES..].to_vec()),
            -1 => Err(Error::Verify),
            _  => unreachable!("Internal error."),
        }
    }
}

#[cfg(test)]
mod tests {
    use crypto::onetimeauth;
    use super::*;

    static C: [u8; onetimeauth::BYTES+3] =
        [126, 79, 196, 241, 56, 117, 222, 2, 146, 56, 182, 245, 242, 134, 22,
         3, 199, 60, 184];
    static M: [u8; 3] = [1, 2, 3];
    static N: [u8; NONCEBYTES] = [0; NONCEBYTES];
    static K: [u8; KEYBYTES] = [0; KEYBYTES];

    #[test]
    fn secretbox_ok() {
        assert_eq!(secretbox(&M, &N, &K), C);
    }

    #[test]
    fn secretbox_open_ok() {
        let m = open(&C, &N, &K)
                        .ok()
                        .expect("failed!");
        assert_eq!(m, &M);
    }

    #[test]
    fn secretbox_open_fail() {
        let bad_n = [1 as u8; NONCEBYTES];
        let bad_k = [1 as u8; KEYBYTES];
        let mut bad_c = C.clone();
        bad_c[0] = bad_c[0] ^ 1;

        let result = open(&C, &bad_n, &K);
        assert!(result == Err(Error::Verify));

        let result = open(&C, &N, &bad_k);
        assert!(result == Err(Error::Verify));

        let result = open(&bad_c, &N, &K);
        assert!(result == Err(Error::Verify));
    }
}
