use ffi;

#[derive(Debug, Eq, PartialEq)]
pub enum CryptoVerifyErr {
    Verify,
}

/// Constant time equality test for two 16-byte arrays.
///
/// The `crypto_verify_16()` function returns Ok(()) if `x[0], x[1], ..., x[15]`
/// are the same as `y[0], y[1], ..., y[15]`.
///
/// This function is safe to use for secrets `x[0], x[1], ..., x[15], y[0],
/// y[1], ..., y[15]`. The time taken by `crypto_verify_16()` is independent of/// the contents of `x[0], x[1], ..., x[15], y[0], y[1], ..., y[15]`. In
/// contrast, the standard C comparison function `memcmp(x,y,16)` takes time
/// that depends on the longest matching prefix of `x` and `y`, often allowing
/// easy timing attacks. 
///
/// # Failures
///
/// If `x != y`, a `CryptoVerifyErr::Verify` is returned.
///
/// # Examples
///
/// ```
/// crypto_verify_16(&x, &y).ok().expect("Verification failed!");
/// ```
///
pub fn crypto_verify_16(x: &[u8; 16], y: &[u8; 16])
-> Result<(), CryptoVerifyErr> {
    unsafe {
        match ffi::crypto_verify_16_tweet(x.as_ptr(), y.as_ptr()) {
            0 => Ok(()),
            -1 => Err(CryptoVerifyErr::Verify),
            _ => unreachable!("Internal error."),
        }
    }
}

/// Constant time equality test for two 32-byte arrays.
///
/// The `crypto_verify_32()` function returns Ok(()) if `x[0], x[1], ..., x[31]`
/// are the same as `y[0], y[1], ..., y[31]`.
///
/// This function is safe to use for secrets `x[0], x[1], ..., x[31], y[0],
/// y[1], ..., y[31]`. The time taken by `crypto_verify_16()` is independent of/// the contents of `x[0], x[1], ..., x[31], y[0], y[1], ..., y[31]`. In
/// contrast, the standard C comparison function `memcmp(x,y,31)` takes time
/// that depends on the longest matching prefix of `x` and `y`, often allowing
/// easy timing attacks. 
///
/// # Failures
///
/// If `x != y`, a `CryptoVerifyErr::Verify` is returned.
///
/// # Examples
///
/// ```
/// crypto_verify_31(&x, &y).ok().expect("Verification failed!");
/// ```
///
pub fn crypto_verify_32(x: &[u8; 32], y: &[u8; 32])
-> Result<(), CryptoVerifyErr> {
    unsafe {
        match ffi::crypto_verify_32_tweet(x.as_ptr(), y.as_ptr()) {
            0 => Ok(()),
            -1 => Err(CryptoVerifyErr::Verify),
            _ => unreachable!("Internal error."),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crypto_verify_16_ok() {
        let x = [0 as u8; 16];
        let y = [0 as u8; 16];
        let result = crypto_verify_16(&x, &y).unwrap();
        assert_eq!(result, ());
    }

    #[test]
    fn crypto_verify_16_fail() {
        let x = [0 as u8; 16];
        let mut y = [0 as u8; 16];
        y[4] = 1;
        let result = crypto_verify_16(&x, &y);
        assert_eq!(result, Err(CryptoVerifyErr::Verify));
    }

    #[test]
    fn crypto_verify_32_ok() {
        let x = [0 as u8; 32];
        let y = [0 as u8; 32];
        let result = crypto_verify_32(&x, &y).unwrap();
        assert_eq!(result, ());
    }

    #[test]
    fn crypto_verify_32_fail() {
        let x = [0 as u8; 32];
        let mut y = [0 as u8; 32];
        y[24] = 1;
        let result = crypto_verify_32(&x, &y);
        assert_eq!(result, Err(CryptoVerifyErr::Verify));
    }
}
