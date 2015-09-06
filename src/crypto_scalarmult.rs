use ffi;

#[derive(Debug, Eq, PartialEq)]
pub enum CryptoScalarmultErr {
    Scalarmult,
    ScalarmultBase,
}

/// Multiply a group element by an integer.
///
/// This function multiplies a group element `p` by an integer `n`. It returns
/// the resulting group element `q` of length `crypto_scalarmult_BYTES`.
///
/// # Failures
///
/// If an internal error occurs, `CryptoScalarmultErr::Scalarmult` is returned.
///
/// # Examples
///
/// Multiply Bob's public key by Alice's secret key to obtain a shared secret:
///
/// ```
/// let shared_secret = crypto_scalarmult(alice_sk, bob_pk)
///                         .ok()
///                         .expect("scalarmult failed!");
/// ```
pub fn crypto_scalarmult(n: &[u8; ffi::crypto_scalarmult_SCALARBYTES],
                         p: &[u8; ffi::crypto_scalarmult_BYTES])
-> Result<[u8; ffi::crypto_scalarmult_BYTES], CryptoScalarmultErr> {

    let mut q = [0 as u8; ffi::crypto_scalarmult_BYTES];

    unsafe {
        match ffi::crypto_scalarmult_curve25519_tweet(
                        q.as_mut_ptr(),
                        n.as_ptr(),
                        p.as_ptr()) {
            0 => Ok(q),
            _ => Err(CryptoScalarmultErr::Scalarmult),
        }
    }
}

/// Compute the scalar product of a standard group element and an integer.
///
/// The `crypto_scalarmult_base()` function computes the scalar product of a
/// standard group element and an integer `n`. It returns the resulting group
/// element `q` of length `crypto_scalarmult_BYTES`.
///
/// # Failures
///
/// A `CryptoScalarmultErr::ScalarmultBase` is returned if an internal error
/// occurs.
///
pub fn crypto_scalarmult_base(n: &[u8; ffi::crypto_scalarmult_SCALARBYTES])
-> Result<[u8; ffi::crypto_scalarmult_BYTES], CryptoScalarmultErr> {

    let mut q = [0 as u8; ffi::crypto_scalarmult_BYTES];

    unsafe {
        match ffi::crypto_scalarmult_curve25519_tweet_base(
                        q.as_mut_ptr(),
                        n.as_ptr()) {
            0 => Ok(q),
            _ => Err(CryptoScalarmultErr::ScalarmultBase),
        }
    }
}

#[cfg(test)]
mod tests {
    use ffi;
    use super::*;

    static ALICE_SK: [u8; ffi::crypto_box_SECRETKEYBYTES] =
        [57, 205, 241, 233, 180, 183, 151, 187, 107, 78, 102, 249, 229, 237,
         84, 15, 141, 184, 171, 156, 67, 151, 50, 70, 39, 6, 151, 96, 133, 35,
         153, 107];
    static ALICE_PK: [u8; ffi::crypto_box_PUBLICKEYBYTES] =
        [69, 160, 229, 23, 37, 18, 235, 18, 172, 96, 127, 27, 116, 184, 29,
         126, 110, 167, 201, 252, 47, 24, 75, 52, 37, 36, 22, 233, 195, 126,
         120, 112];
    static BOB_SK: [u8; ffi::crypto_box_SECRETKEYBYTES] =
        [176, 134, 132, 212, 9, 176, 83, 50, 95, 0, 85, 176, 31, 248, 219,
         254, 242, 213, 159, 137, 52, 90, 244, 151, 223, 87, 255, 68, 127,
         106, 213, 79];
    static BOB_PK: [u8; ffi::crypto_box_PUBLICKEYBYTES] =
        [160, 181, 63, 165, 91, 192, 71, 127, 69, 218, 113, 100, 33, 110, 128,
         153, 39, 10, 84, 122, 221, 156, 231, 102, 143, 63, 64, 70, 223, 136,
         134, 94];
    static SMULT_OUT: [u8; ffi::crypto_scalarmult_BYTES] =
        [38, 16, 230, 128, 26, 181, 100, 196, 135, 142, 113, 109, 103, 105,
         109, 153, 186, 139, 150, 176, 182, 70, 180, 247, 24, 229, 150, 84,
         224, 25, 0, 20];
    static BASE_OUT: [u8; ffi::crypto_scalarmult_BYTES] =
        [69, 160, 229, 23, 37, 18, 235, 18, 172, 96, 127, 27, 116, 184, 29,
         126, 110, 167, 201, 252, 47, 24, 75, 52, 37, 36, 22, 233, 195, 126,
         120, 112];

    #[test]
    fn crypto_scalarmult_ok() {
        let r1 = crypto_scalarmult(&ALICE_SK, &BOB_PK)
                    .ok()
                    .expect("failed!");
        let r2 = crypto_scalarmult(&BOB_SK, &ALICE_PK)
                    .ok()
                    .expect("failed!");
        assert_eq!(r1, r2);
        assert_eq!(r1, SMULT_OUT);
    }

    #[test]
    fn crypto_scalarmult_base_ok() {
        let r1 = crypto_scalarmult_base(&ALICE_SK)
                    .ok()
                    .expect("failed!");
        assert_eq!(r1, BASE_OUT);
    }
}
