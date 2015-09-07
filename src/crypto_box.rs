use ffi;

pub const PUBLICKEYBYTES:   usize = 32;
pub const SECRETKEYBYTES:   usize = 32;
pub const NONCEBYTES:       usize = 24;
pub const ZEROBYTES:        usize = 32;
pub const BOXZEROBYTES:     usize = 16;

#[derive(Debug, Eq, PartialEq)]
pub enum Error {
    Verify,
}

/// Generate a Curve25519 keypair.
///
/// The `crypto_box_keypair()` function randomly generates a secret key and a
/// corresponding public key. It puts the secret key into `sk` and returns the
/// public key. It guarantees that `sk` has `crypto_box::SECRETKEYBYTES` bytes
/// and that `pk` has `crypto_box::PUBLICKEYBYTES` bytes.
///
/// # Examples
///
/// Generating a keypair:
///
/// ```
/// let mut sk = [0 as u8; crypto_box::SECRETKEYBYTES];
/// let pk = crypto_box_keypair(&mut sk).ok().expect("Keypair failed!");
/// ```
pub fn crypto_box_keypair(sk: &mut [u8; SECRETKEYBYTES])
-> [u8; PUBLICKEYBYTES] {

    let mut pk = [0 as u8; PUBLICKEYBYTES];

    unsafe {
        match ffi::crypto_box_curve25519xsalsa20poly1305_tweet_keypair(
                        pk.as_mut_ptr(),
                        sk.as_mut_ptr()) {
            0 => pk,
            _ => unreachable!("Internal error."),
        }
    }
}

/// Encrypt and authenticate a message.
///
/// The `crypto_box()` function encrypts and authenticates a message `m` using
/// the sender's secret key `sk`, the receiver's public key `pk`, and a nonce
/// `n`. The `crypto_box()` function returns the resulting ciphertext `c`.
///
/// # Examples
///
/// Encrypting a message:
///
/// ```
/// let ciphertext = crypto_box(&plaintext, &nonce, &their_public_key,
///                             &my_secret_key).ok().expect("Box Failed!");
/// ```
pub fn crypto_box(m:  &[u8],
                  n:  &[u8; NONCEBYTES],
                  pk: &[u8; PUBLICKEYBYTES],
                  sk: &[u8; SECRETKEYBYTES])
-> Vec<u8> {

    let mut padded_m = vec![0 as u8; ZEROBYTES];
    padded_m.extend(m.iter().cloned());
    let mut c = vec![0 as u8; padded_m.len()];

    unsafe {
        match ffi::crypto_box_curve25519xsalsa20poly1305_tweet(
                        c.as_mut_ptr(),
                        padded_m.as_ptr(),
                        padded_m.len() as u64,
                        n.as_ptr(),
                        pk.as_ptr(),
                        sk.as_ptr()) {
            0 => c[BOXZEROBYTES..].to_vec(),
            _ => unreachable!("Internal error."),
        }
    }
}

/// Verify and decrypt a ciphertext.
///
/// The `crypto_box_open()` function verifies and decrypts a ciphertext `c`
/// using the receiver's secret key `sk`, the sender's public key `pk`, and a
/// nonce `n`. The `crypto_box_open()` function returns the resulting plaintext
/// `m`.
///
/// # Failures
///
/// If the ciphertext fails verification, an `Err(Error::Verify)`
/// is returned.
///
/// # Examples
///
/// Verify and decrypt a message:
///
/// ```
/// let plaintext = crypto_box_open(&ciphertext, &nonce, &their_public_key,
///                                 &my_secret_key)
///                                     .ok()
///                                     .expect("Verification Failed!");
/// ```
///
pub fn crypto_box_open(c:  &[u8],
                       n:  &[u8; NONCEBYTES],
                       pk: &[u8; PUBLICKEYBYTES],
                       sk: &[u8; SECRETKEYBYTES])
-> Result<Vec<u8>, Error> {

    let mut padded_c = vec![0 as u8; BOXZEROBYTES];
    padded_c.extend(c.iter().cloned());
    let mut m = vec![0 as u8; padded_c.len()];

    unsafe {
        match ffi::crypto_box_curve25519xsalsa20poly1305_tweet_open(
                        m.as_mut_ptr(),
                        padded_c.as_ptr(),
                        padded_c.len() as u64,
                        n.as_ptr(),
                        pk.as_ptr(),
                        sk.as_ptr()) {
            0  => Ok(m[ZEROBYTES..m.len()].to_vec()),
            -1 => Err(Error::Verify),
            _  => unreachable!("Internal error."),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    static ALICE_SK: [u8; SECRETKEYBYTES] =
        [244, 198, 125, 80, 217, 96, 158, 20, 19, 178, 135, 17, 29, 153, 157,
         132, 149, 35, 119, 79, 213, 153, 42, 63, 30, 103, 132, 4, 166, 247,
         16, 19];
    static ALICE_PK: [u8; PUBLICKEYBYTES] =
        [63, 195, 253, 143, 164, 43, 87, 145, 223, 184, 237, 180, 245, 246,
         118, 139, 188, 95, 209, 250, 47, 2, 247, 214, 77, 149, 202, 126, 200,
         238, 63, 30];
    static BOB_SK: [u8; SECRETKEYBYTES] =
        [191, 47, 36, 109, 103, 198, 78, 27, 47, 111, 50, 117, 34, 249, 175,
         23, 47, 113, 2, 67, 199, 95, 33, 79, 148, 168, 12, 97, 22, 65, 198,
         80];
    static BOB_PK: [u8; PUBLICKEYBYTES] =
        [249, 6, 3, 156, 96, 233, 80, 243, 198, 63, 57, 145, 19, 15, 71, 205,
         68, 203, 150, 6, 90, 255, 66, 74, 103, 162, 90, 76, 76, 175, 135, 51];
    static NONCE: [u8; NONCEBYTES] = [0; NONCEBYTES];
    static M: [u8; 3] = [1, 2, 3];
    static CIPHERTEXT: [u8; 19] = [136, 190, 177, 116, 32, 235, 144, 191, 211,
                                   18, 72, 175, 159, 123, 205, 22, 197, 109,
                                   42];

    #[test]
    #[allow(unused_variables)]
    fn crypto_box_keypair_ok() {
        let mut sk = [0 as u8; SECRETKEYBYTES];
        let pk = crypto_box_keypair(&mut sk);
    }

    #[test]
    fn crypto_box_ok() {
        let c = crypto_box(&M, &NONCE, &BOB_PK, &ALICE_SK);
        assert_eq!(c, &CIPHERTEXT);
    }

    #[test]
    fn crypto_box_open_ok() {
        let m = crypto_box_open(&CIPHERTEXT, &NONCE, &ALICE_PK, &BOB_SK)
                    .ok()
                    .expect("Box Open Failed!");
        assert_eq!(m, &M);
    }

    #[test]
    fn crypto_box_open_fail() {
        let mut bad_c = CIPHERTEXT.clone();
        bad_c[0] = bad_c[0] ^ 1;

        let mut bad_n = NONCE.clone();
        bad_n[0] = bad_n[0] ^ 1;

        let mut bad_pk = ALICE_PK.clone();
        bad_pk[0] = bad_pk[0] ^ 1;

        let mut bad_sk = BOB_SK.clone();
        bad_sk[1] = bad_sk[1] ^ 1;

        let result = crypto_box_open(&bad_c, &NONCE, &ALICE_PK, &BOB_SK);
        assert_eq!(result, Err(Error::Verify));

        let result = crypto_box_open(&CIPHERTEXT, &bad_n, &ALICE_PK, &BOB_SK);
        assert_eq!(result, Err(Error::Verify));

        let result = crypto_box_open(&CIPHERTEXT, &NONCE, &bad_pk, &BOB_SK);
        assert_eq!(result, Err(Error::Verify));

        let result = crypto_box_open(&CIPHERTEXT, &NONCE, &ALICE_PK, &bad_sk);
        assert_eq!(result, Err(Error::Verify));
    }
}
