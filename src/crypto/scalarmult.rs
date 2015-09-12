use ffi;

pub const BYTES:        usize = 32;
pub const SCALARBYTES:  usize = 32;

/// Multiply a group element by an integer.
///
/// This function multiplies a group element `p` by an integer `n`. It returns
/// the resulting group element `q` of length `scalarmult::BYTES`.
///
/// # Examples
///
/// Multiply Bob's public key by Alice's secret key to obtain a shared secret:
///
/// ```
/// # use tweetnaclrs::crypto::scalarmult;
/// # let alice_sk = [0 as u8; 32];
/// # let bob_pk = [1 as u8; 32];
/// let shared_secret = scalarmult::scalarmult(&alice_sk, &bob_pk);
/// ```
pub fn scalarmult(n: &[u8; SCALARBYTES],
                  p: &[u8; BYTES])
-> [u8; BYTES] {

    let mut q = [0 as u8; BYTES];

    unsafe {
        match ffi::crypto_scalarmult_curve25519_tweet(
                        q.as_mut_ptr(),
                        n.as_ptr(),
                        p.as_ptr()) {
            0 => q,
            _ => unreachable!("Internal error."),
        }
    }
}

/// Compute the scalar product of a standard group element and an integer.
///
/// The `scalarmult_base()` function computes the scalar product of a
/// standard group element and an integer `n`. It returns the resulting group
/// element `q` of length `scalarmult::BYTES`.
pub fn scalarmult_base(n: &[u8; SCALARBYTES]) -> [u8; BYTES] {

    let mut q = [0 as u8; BYTES];

    unsafe {
        match ffi::crypto_scalarmult_curve25519_tweet_base(
                        q.as_mut_ptr(),
                        n.as_ptr()) {
            0 => q,
            _ => unreachable!("Internal error."),
        }
    }
}

#[cfg(test)]
mod tests {
    use crypto::cbox;
    use super::*;

    static ALICE_SK: [u8; cbox::SECRETKEYBYTES] =
        [57, 205, 241, 233, 180, 183, 151, 187, 107, 78, 102, 249, 229, 237,
         84, 15, 141, 184, 171, 156, 67, 151, 50, 70, 39, 6, 151, 96, 133, 35,
         153, 107];
    static ALICE_PK: [u8; cbox::PUBLICKEYBYTES] =
        [69, 160, 229, 23, 37, 18, 235, 18, 172, 96, 127, 27, 116, 184, 29,
         126, 110, 167, 201, 252, 47, 24, 75, 52, 37, 36, 22, 233, 195, 126,
         120, 112];
    static BOB_SK: [u8; cbox::SECRETKEYBYTES] =
        [176, 134, 132, 212, 9, 176, 83, 50, 95, 0, 85, 176, 31, 248, 219,
         254, 242, 213, 159, 137, 52, 90, 244, 151, 223, 87, 255, 68, 127,
         106, 213, 79];
    static BOB_PK: [u8; cbox::PUBLICKEYBYTES] =
        [160, 181, 63, 165, 91, 192, 71, 127, 69, 218, 113, 100, 33, 110, 128,
         153, 39, 10, 84, 122, 221, 156, 231, 102, 143, 63, 64, 70, 223, 136,
         134, 94];
    static SMULT_OUT: [u8; BYTES] =
        [38, 16, 230, 128, 26, 181, 100, 196, 135, 142, 113, 109, 103, 105,
         109, 153, 186, 139, 150, 176, 182, 70, 180, 247, 24, 229, 150, 84,
         224, 25, 0, 20];
    static BASE_OUT: [u8; BYTES] =
        [69, 160, 229, 23, 37, 18, 235, 18, 172, 96, 127, 27, 116, 184, 29,
         126, 110, 167, 201, 252, 47, 24, 75, 52, 37, 36, 22, 233, 195, 126,
         120, 112];

    #[test]
    fn scalarmult_ok() {
        let q1 = scalarmult(&ALICE_SK, &BOB_PK);
        let q2 = scalarmult(&BOB_SK, &ALICE_PK);
        assert_eq!(q1, q2);
        assert_eq!(q1, SMULT_OUT);
    }

    #[test]
    fn scalarmult_base_ok() {
        let q1 = scalarmult_base(&ALICE_SK);
        assert_eq!(q1, BASE_OUT);
    }
}
