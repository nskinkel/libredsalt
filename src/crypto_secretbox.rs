use crypto_onetimeauth;
use ffi;

#[derive(Debug, Eq, PartialEq)]
pub enum CryptoSecretBoxErr {
    SecretBox,
    SecretBoxOpen,
}

/// Encrypt and authenticate a message.
///
/// The `crypto_secretbox()` function encrypts and authenticates a message `m`
/// using a secret key `k` and a nonce `n`. The `crypto_secretbox()` function
/// returns the resulting ciphertext `c`.
///
/// # Failures
/// A `CryptoSecretBoxErr::SecretBox` is returned if an internal error occurs.
///
/// # Examples
///
/// Encrypt and authenticate a message `m`:
///
/// ```
/// let ciphertext = crypto_secretbox(&plaintext, &nonce, &key);
/// ```
///
pub fn crypto_secretbox(m: &[u8], n: &[u8; ffi::crypto_secretbox_NONCEBYTES],
                        k: &[u8; ffi::crypto_secretbox_KEYBYTES])
-> Result<Vec<u8>, CryptoSecretBoxErr> {

    let mut padded_m = vec![0 as u8; ffi::crypto_secretbox_ZEROBYTES];
    padded_m.extend(m.iter().cloned());
    let mut c = vec![0 as u8; ffi::crypto_secretbox_BOXZEROBYTES +
                              crypto_onetimeauth::BYTES +
                              m.len()];

    unsafe {
        match ffi::crypto_secretbox_xsalsa20poly1305_tweet(
                        c.as_mut_ptr(),
                        padded_m.as_ptr(),
                        padded_m.len() as u64,
                        n.as_ptr(),
                        k.as_ptr()) {
            0 => Ok(c[ffi::crypto_secretbox_BOXZEROBYTES..c.len()].to_vec()),
            _ => Err(CryptoSecretBoxErr::SecretBox),
        }
    }
}

/// Verify and decrypt a message.
///
/// The `crypto_secretbox_open()` function verifies and decrypts a ciphertext
/// `c` using a secret key `k` and a nonce `n`. The `crypto_secretbox_open()`
/// function returns the resulting plaintext `m`.
///
/// # Failures
///
/// A `CryptoSecretBoxErr::SecretBoxOpen` is returned if the ciphertext fails
/// verification.
///
/// # Examples
///
/// Verify and decrypt a ciphertext:
///
/// ```
/// let plaintext = crypto_secretbox_open(&ciphertext, &nonce, &key)
///                        .ok()
///                        .expect("Verification failed!");
/// ```
///
pub fn crypto_secretbox_open(c: &[u8],
                             n: &[u8; ffi::crypto_secretbox_NONCEBYTES],
                             k: &[u8; ffi::crypto_secretbox_KEYBYTES])
-> Result<Vec<u8>, CryptoSecretBoxErr> {

    let mut padded_c = vec![0 as u8; ffi::crypto_secretbox_BOXZEROBYTES];
    padded_c.extend(c.iter().cloned());
    let mut m = vec![0 as u8; padded_c.len()];

    unsafe {
        match ffi::crypto_secretbox_xsalsa20poly1305_tweet_open(
                        m.as_mut_ptr(),
                        padded_c.as_ptr(),
                        padded_c.len() as u64,
                        n.as_ptr(),
                        k.as_ptr()) {
            0 => Ok(m[ffi::crypto_secretbox_ZEROBYTES..m.len()].to_vec()),
            _ => Err(CryptoSecretBoxErr::SecretBoxOpen),
        }
    }
}

#[cfg(test)]
mod tests {
    use crypto_onetimeauth;
    use ffi;
    use super::*;

    static C: [u8; crypto_onetimeauth::BYTES+3] =
        [126, 79, 196, 241, 56, 117, 222, 2, 146, 56, 182, 245, 242, 134, 22,
         3, 199, 60, 184];
    static M: [u8; 3] = [1, 2, 3];
    static N: [u8; ffi::crypto_secretbox_NONCEBYTES] =
        [0; ffi::crypto_secretbox_NONCEBYTES];
    static K: [u8; ffi::crypto_secretbox_KEYBYTES] =
        [0; ffi::crypto_secretbox_KEYBYTES];

    #[test]
    fn crypto_secretbox_ok() {
        let c = crypto_secretbox(&M, &N, &K).ok().expect("failed!");
        assert_eq!(c, C);
    }

    #[test]
    fn crypto_secretbox_open_ok() {
        let m = crypto_secretbox_open(&C, &N, &K)
                        .ok()
                        .expect("failed!");
        assert_eq!(m, &M);
    }

    #[test]
    fn crypto_secretbox_open_fail() {
        let bad_n = [1 as u8; ffi::crypto_secretbox_NONCEBYTES];
        let bad_k = [1 as u8; ffi::crypto_secretbox_KEYBYTES];
        let mut bad_c = C.clone();
        bad_c[0] = bad_c[0] ^ 1;

        let result = crypto_secretbox_open(&C, &bad_n, &K);
        assert!(result == Err(CryptoSecretBoxErr::SecretBoxOpen));

        let result = crypto_secretbox_open(&C, &N, &bad_k);
        assert!(result == Err(CryptoSecretBoxErr::SecretBoxOpen));

        let result = crypto_secretbox_open(&bad_c, &N, &K);
        assert!(result == Err(CryptoSecretBoxErr::SecretBoxOpen));
    }
}
