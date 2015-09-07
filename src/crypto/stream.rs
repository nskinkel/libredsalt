use ffi;

pub const KEYBYTES:     usize = 32;
pub const NONCEBYTES:   usize = 24;

/// Produce a byte stream as a function of a key and a nonce.
///
/// The `stream()` function produces a `clen`-byte stream `c` as a
/// function of a secret key `k` and a nonce `n`.
///
/// # Examples
///
/// Generate a 32-byte stream using a nonce `n` and a secret key `sk`:
///
/// ```
/// # use tweetnaclrs::crypto::stream;
/// # let n = [0 as u8; 24];
/// # let sk = [1 as u8; 32];
/// let clen: u64 = 32;
/// let cstream = stream::stream(clen, &n, &sk);
/// ```
pub fn stream(clen: u64,
              n: &[u8; NONCEBYTES],
              k: &[u8; KEYBYTES])
-> Vec<u8> {

    let mut out = vec![0 as u8; clen as usize];

    unsafe {
        match ffi::crypto_stream_xsalsa20_tweet(
                        out.as_mut_ptr(),
                        clen,
                        n.as_ptr(),
                        k.as_ptr()) {
            0 => out,
            _ => unreachable!("Internal error."),
        }
    }
}

/// Encrypt a message using a secret key and a nonce.
///
/// The `xor()` function encrypts a message `m` using a secret
/// key `k` and a nonce `n`. The `xor()` function returns the
/// ciphertext `c`.
///
/// The `xor()` function guarantees that the ciphertext has the
/// same length as the plaintext, and is the plaintext xor the output of
/// `stream()`. Consequently `xor()` can also be used to
/// decrypt. 
///
/// # Examples
///
/// Encrypt a message `m` with a key `k` and a nonce `n`:
///
/// ```
/// # use tweetnaclrs::crypto::stream;
/// # let n = [1 as u8; 24];
/// # let k = [2 as u8; 32];
/// let m = [1 as u8, 2, 3];
/// let ciphertext = stream::xor(&m, &n, &k);
/// ```
pub fn xor(m: &[u8],
           n: &[u8; NONCEBYTES],
           k: &[u8; KEYBYTES])
-> Vec<u8> {

    let mut c = vec![0 as u8; m.len()];
    
    unsafe {
        match ffi::crypto_stream_xsalsa20_tweet_xor(
                        c.as_mut_ptr(),
                        m.as_ptr(),
                        m.len() as u64,
                        n.as_ptr(),
                        k.as_ptr()) {
            0 => c,
            _ => unreachable!("Internal error."),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    static K: [u8; KEYBYTES] =
        [1, 24, 23, 52, 179, 101, 151, 197, 129, 89, 94, 225, 204, 19, 90, 21,
         211, 193, 151, 239, 163, 209, 83, 108, 15, 150, 49, 227, 9, 14, 141,
         51];
    static N: [u8; NONCEBYTES] = [0; NONCEBYTES];
    static C: [u8; 32] = [132, 132, 197, 162, 195, 160, 109, 176, 205, 176,
                          126, 202, 233, 54, 60, 125, 57, 107, 138, 85, 81,
                          206, 124, 46, 125, 96, 99, 209, 74, 5, 88, 14];
    static M: [u8; 32] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                          16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28,
                          29, 30, 31, 32];
    static X: [u8; 32] = [133, 134, 198, 166, 198, 166, 106, 184, 196, 186,
                          117, 198, 228, 56, 51, 109, 40, 121, 153, 65, 68,
                          216, 107, 54, 100, 122, 120, 205, 87, 27, 71, 46];

    #[test]
    fn stream_ok() {
        assert_eq!(stream(32, &N, &K), C);
    }

    #[test]
    fn xor_ok() {
        let c = xor(&M, &N, &K);
        assert_eq!(c, X);
        let m = xor(&c, &N, &K);
        assert_eq!(m, M);
    }
}
