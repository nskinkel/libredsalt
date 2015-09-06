use ffi;

#[derive(Debug, Eq, PartialEq)]
pub enum CryptoHashErr {
    Hash,
}

/// Hash a message.
///
/// The `crypto_hash()` function hashes a message `m` using `SHA512`. It
/// returns a hash `h`. The output length `h.size()` is always
/// `crypto_hash_BYTES()`.
///
/// # Failures
///
/// If an internal hashing error occurs, `CryptoHashErr::Hash` is returned.
///
/// # Examples
///
/// ```
/// let m = [1 as u8, 2, 3];
/// let hashed = crypto_hash(&m);
/// ```
///
pub fn crypto_hash(m: &[u8])
-> Result<[u8; ffi::crypto_hash_BYTES], CryptoHashErr> {

    let mut out = [0 as u8; ffi::crypto_hash_BYTES];

    unsafe {
        match ffi::crypto_hash_sha512_tweet(out.as_mut_ptr(),
                                            m.as_ptr(),
                                            m.len() as u64) {
            0 => Ok(out),
            _ => Err(CryptoHashErr::Hash),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crypto_hash_ok() {
        let m : [u8; 3] = [1, 2, 3];
        let expected : [u8; 64] = [ 39, 134,  76, 197,  33, 154, 149,  26,
                                   122, 110,  82, 184, 200, 221, 223, 105,
                                   129, 208, 152, 218,  22,  88, 217,  98,
                                    88, 200, 112, 178, 200, 141, 251, 203,
                                    81, 132,  26, 234,  23,  42,  40, 186,
                                   250, 106, 121, 115,  17, 101,  88,  70,
                                   119,   6,  96,  69, 201,  89, 237,  15,
                                   153,  41, 104, 141,   4, 222, 252,  41];
        let hashed = match crypto_hash(&m) {
            Ok(v) => v,
            Err(e) => panic!(e),
        };
        assert!(hashed.iter().zip(expected.iter()).all(|(a,b)| a == b));
    }
}
