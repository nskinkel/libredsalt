extern crate rand;
extern crate tweetnaclrs;

use rand::{OsRng, Rng};
use rand::distributions::{IndependentSample, Range};
use tweetnaclrs::crypto::secretbox;

#[test]
fn secretbox8() {
    let mut rng = OsRng::new().ok().expect("OsRng failed!");

    for i in 0..100 {
        let mut k = [0 as u8; secretbox::KEYBYTES];
        let mut n = [0 as u8; secretbox::NONCEBYTES];
        let mut m = vec![0 as u8; i];
        rng.fill_bytes(&mut k);
        rng.fill_bytes(&mut n);
        rng.fill_bytes(&mut m);

        let mut c = secretbox::secretbox(&m, &n, &k);

        let between = Range::new(0, c.len());
        let idx = between.ind_sample(&mut rng);
        c[idx] ^= 1;
        
        let result = secretbox::open(&c, &n, &k);
        assert!(result == Err(secretbox::Error::Verify));
    }
}
