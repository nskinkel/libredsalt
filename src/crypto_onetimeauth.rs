use ffi;

pub const BYTES:    usize = 16;
pub const KEYBYTES: usize = 32;

/// Authenticate a message.
///
/// The `crypto_onetimeauth()` function authenticates a message `m` using a
/// secret key `k`, and returns an authenticator `a`. The authenticator length
/// is always `crypto_onetimeauth::BYTES`.
///
/// # Examples
///
/// Authenticate a message:
///
/// ```
/// let auth = crypto_onetimeauth(&m, &k);
/// ```
pub fn crypto_onetimeauth(m: &[u8], k: &[u8; KEYBYTES]) -> [u8; BYTES] {

    let mut auth = [0 as u8; BYTES];

    unsafe {
        match ffi::crypto_onetimeauth_poly1305_tweet(
                        auth.as_mut_ptr(),
                        m.as_ptr(),
                        m.len() as u64,
                        k.as_ptr()) {
            0 => auth,
            _ => unreachable!("Internal error."),
        }
    }
}

/// Verify a message.
///
/// This function returns `true` if `a` is a correct authenticator of a
/// message `m` under the secret key `k`
///
/// # Failures
///
/// `false` is returned if `m` fails verification.
///
/// # Examples
///
/// ```
/// let verified = crypto_onetimeauth_verify(&a, &m, &k);
/// ```
pub fn crypto_onetimeauth_verify(a: &[u8; BYTES],
                                 m: &[u8],
                                 k: &[u8; KEYBYTES])
-> bool {

    unsafe {
        match ffi::crypto_onetimeauth_poly1305_tweet_verify(
                        a.as_ptr(),
                        m.as_ptr(),
                        m.len() as u64,
                        k.as_ptr()) {
            0  => true,
            -1 => false,
            _  => unreachable!("Internal error."),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    static M: [u8; 3] = [1, 2, 3];
    static K: [u8; KEYBYTES] =
        [94, 160, 2, 50, 215, 69, 14, 177, 153, 175, 171, 118, 23, 86, 2, 147,
         51, 121, 188, 153, 175, 42, 81, 94, 184, 117, 143, 111, 237, 69, 51,
         215];
    static A: [u8; BYTES] =
        [201, 163, 29, 224, 47, 33, 105, 33, 195, 102, 99, 116, 193, 131, 36,
         245];

    #[test]
    pub fn crypto_onetimeauth_ok() {
        let result = crypto_onetimeauth(&M, &K);
        assert_eq!(result, A);
    }

    #[test]
    pub fn crypto_onetimeauth_verify_ok() {
        assert!(crypto_onetimeauth_verify(&A, &M, &K));
    }

    #[test]
    pub fn crypto_onetimeauth_verify_fail() {
        let mut bad_a = A.clone();
        bad_a[0] = bad_a[0] ^ 1;

        let mut bad_m = M.clone();
        bad_m[0] = bad_m[0] ^ 1;

        let mut bad_k = K.clone();
        bad_k[0] = bad_k[0] ^ 1;

        assert!(!crypto_onetimeauth_verify(&bad_a, &M, &K));
        assert!(!crypto_onetimeauth_verify(&A, &bad_m, &K));
        assert!(!crypto_onetimeauth_verify(&A, &M, &bad_k));
    }
}
