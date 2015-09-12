extern crate rand;
extern crate tweetnaclrs;

use rand::{OsRng, Rng};
use tweetnaclrs::crypto::secretbox;

#[test]
fn secretbox7() {
    
    let mut rng = OsRng::new().ok().expect("OsRng failed!");
    
    for i in 0..100 {
        let mut k = [0 as u8; secretbox::KEYBYTES];
        let mut n = [0 as u8; secretbox::NONCEBYTES];
        let mut m = vec![0 as u8; i];
        rng.fill_bytes(&mut k);
        rng.fill_bytes(&mut n);
        rng.fill_bytes(&mut m);

        let c = secretbox::secretbox(&m, &n, &k);
        let r = secretbox::open(&c, &n, &k).ok().expect("open failed!");
        assert!(m.iter().zip(r.iter()).all(|(a,b)| a == b));
    }
}
