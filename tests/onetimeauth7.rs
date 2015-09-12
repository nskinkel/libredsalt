extern crate rand;
extern crate tweetnaclrs;

use rand::{OsRng, Rng};
use rand::distributions::{IndependentSample, Range};
use tweetnaclrs::crypto::onetimeauth;

#[test]
fn onetimeauth7() {
    let mut rng = OsRng::new().ok().expect("OsRng failed!");
    
    for i in 0..1000 {
        let mut k = [0 as u8; onetimeauth::KEYBYTES];
        rng.fill_bytes(&mut k);
        
        let mut c = vec![0 as u8; i];
        rng.fill_bytes(&mut c);

        let a = onetimeauth::onetimeauth(&c, &k); 
        assert!(onetimeauth::verify(&a, &c, &k));

        if i > 0 {
            let between = Range::new(0, i); 
            let idx = between.ind_sample(&mut rng);

            let mut c1 = c.clone();
            c1[idx] ^= 1;

            assert!(!onetimeauth::verify(&a, &c1, &k));

            let between = Range::new(0, onetimeauth::BYTES);
            let idx = between.ind_sample(&mut rng);
            
            let mut a1 = a.clone();
            a1[idx] ^= 1;

            assert!(!onetimeauth::verify(&a1, &c, &k));
        }
    }
}
