extern crate libc;

mod ffi;

#[test]
fn it_works() {
    let mut pk = [0u8; ffi::crypto_box_PUBLICKEYBYTES as usize];
    let mut sk = [0u8; ffi::crypto_box_SECRETKEYBYTES as usize];
    let ret = crypto_box_keypair(&mut pk, &mut sk);
    println!("{}", ret);
}

pub fn crypto_box_keypair(pk: &mut[u8], sk: &mut[u8]) -> i32 {
    // TODO: Assert correctly sized slices.
    unsafe {
        ffi::crypto_box_keypair(pk.as_mut_ptr(), sk.as_mut_ptr())
    }
}
