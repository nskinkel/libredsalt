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
    padded_m.extend(m.iter().clone());
    let mut c = vec![0 as u8; ffi::crypto_secretbox_BOXZEROBYTES +
                              ffi::crypto_onetimeauth_BYTES + 
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
    padded_c.extend(c.iter().clone());
    let mut m = vec![0 as u8; padded_c.len()];

    unsafe {
        match ffi::crypto_secretbox_xsalsa20poly1305_tweet_open(
                        m.as_mut_ptr(),
                        padded_c.as_ptr(),
                        padded_c.len() as u64,
                        n.as_ptr(),
                        k.as_ptr()) {
            0 => Ok(m[ffi::crypto_box_ZEROBYTES..m.len()].to_vec()),
            _ => Err(CryptoSecretBoxErr::SecretBoxOpen),
        }
    }
}

#[cfg(test)]
mod tests {
    use ffi;
    use super::*;

    #[test]
    fn crypto_secretbox_ok() {
        let m = [1 as u8, 2, 3];
        let n = [0 as u8; ffi::crypto_secretbox_NONCEBYTES];
        let k = [0 as u8; ffi::crypto_secretbox_KEYBYTES];

        let expected = [126 as u8, 79, 196, 241, 56, 117, 222, 2, 146, 56, 182,
                        245, 242, 134, 22, 3, 199, 60, 184];

        let ciphertext = match crypto_secretbox(&m, &n, &k) {
            Ok(v) => v,
            Err(e) => panic!(e),
        };
        assert!(ciphertext.iter().zip(expected.iter()).all(|(a,b)| a == b));
    }

    #[test]
    fn crypto_secretbox_open_ok() {
        let expected = [1 as u8, 2, 3];
        let n = [0 as u8; ffi::crypto_secretbox_NONCEBYTES];
        let k = [0 as u8; ffi::crypto_secretbox_KEYBYTES];
        let ciphertext = [126 as u8, 79, 196, 241, 56, 117, 222, 2, 146, 56,
                          182, 245, 242, 134, 22, 3, 199, 60, 184];

        let m = match crypto_secretbox_open(&ciphertext, &n, &k) {
            Ok(v) => v,
            Err(e) => panic!(e),
        };
        assert_eq!(m, &expected);
    }

    #[test]
    fn crypto_secretbox_open_fail() {
        let n = [0 as u8; ffi::crypto_secretbox_NONCEBYTES];
        let k = [0 as u8; ffi::crypto_secretbox_KEYBYTES];
        let c = [126 as u8, 79, 196, 241, 56, 117, 222, 2, 146, 56, 182, 245,
                 242, 134, 22, 3, 199, 60, 184];
        let bad_n = [1 as u8; ffi::crypto_secretbox_NONCEBYTES];
        let bad_k = [1 as u8; ffi::crypto_secretbox_KEYBYTES];
        let mut bad_c = c.clone();
        bad_c[0] = bad_c[0] ^ 1;

        let result = crypto_secretbox_open(&c, &bad_n, &k);
        assert!(result == Err(CryptoSecretBoxErr::SecretBoxOpen));

        let result = crypto_secretbox_open(&c, &n, &bad_k);
        assert!(result == Err(CryptoSecretBoxErr::SecretBoxOpen));

        let result = crypto_secretbox_open(&bad_c, &n, &k);
        assert!(result == Err(CryptoSecretBoxErr::SecretBoxOpen));
    }
}
