extern crate rand;
extern crate tweetnaclrs;

use rand::{OsRng, Rng};
use tweetnaclrs::crypto::cbox;

#[test]
fn cbox5() {
    let mut rng = OsRng::new().ok().expect("OsRng failed!");

    for i in 0..100 {
        let mut alicesk = [0 as u8; cbox::SECRETKEYBYTES];
        let alicepk = cbox::keypair(&mut alicesk);

        let mut bobsk = [0 as u8; cbox::SECRETKEYBYTES];
        let bobpk = cbox::keypair(&mut bobsk);

        let mut nonce = [0 as u8; cbox::NONCEBYTES];
        rng.fill_bytes(&mut nonce);
        
        let mut m1 = vec![0 as u8; i];
        rng.fill_bytes(&mut m1);

        let c = cbox::cbox(&m1, &nonce, &bobpk, &alicesk);
        let m2 = cbox::open(&c, &nonce, &alicepk, &bobsk)
                            .ok()
                            .expect("failed!");
        assert!(m1.iter().zip(m2.iter()).all(|(a,b)| a == b));
    }
}
