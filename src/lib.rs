extern crate libc;
extern crate rand;

mod ffi;

pub mod crypto {
    pub mod cbox;
    pub mod hash;
    pub mod onetimeauth;
    pub mod scalarmult;
    pub mod secretbox;
    pub mod sign;
    pub mod stream;
    pub mod verify;
}

pub mod randombytes;
