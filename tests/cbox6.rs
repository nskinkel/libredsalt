extern crate rand;
extern crate tweetnaclrs;

use rand::{OsRng, Rng};
use rand::distributions::{IndependentSample, Range};
use tweetnaclrs::crypto::cbox;

#[test]
fn cbox6() {

    let mut rng = OsRng::new().ok().expect("OsRng failed!");

    for i in 0..100 {
        let mut alicesk = [0 as u8; cbox::SECRETKEYBYTES];
        let alicepk = cbox::keypair(&mut alicesk);

        let mut bobsk = [0 as u8; cbox::SECRETKEYBYTES];
        let bobpk = cbox::keypair(&mut bobsk);

        let mut nonce = [0 as u8; cbox::NONCEBYTES];
        rng.fill_bytes(&mut nonce);

        let mut m = vec![0 as u8; i];
        rng.fill_bytes(&mut m);

        let mut c = cbox::cbox(&m, &nonce, &bobpk, &alicesk);

        let between = Range::new(0, c.len());
        let idx = between.ind_sample(&mut rng);
        c[idx] = rng.gen::<u8>();

        let result = cbox::open(&c, &nonce,  &alicepk, &bobsk);
        assert!(result == Err(cbox::Error::Verify));
    }
}
