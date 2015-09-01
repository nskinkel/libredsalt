use rand::{OsRng, Rng};
use std::slice;

#[no_mangle]
pub unsafe extern fn randombytes(buf: *mut u8, nbytes: u64) {
    assert!(!buf.is_null());
    let mut rng = OsRng::new().ok().expect("OSRNG failed.");
    let mut bytes = slice::from_raw_parts_mut(buf, nbytes as usize);
    rng.fill_bytes(bytes);
}


