#![feature(test)]
extern crate test;

use sha2::{Sha224, Sha256, Sha512};
use test::Bencher;

macro_rules! define_benchmark {
    ($name:ident, $hash:ty) => {
        #[bench]
        fn $name(b: &mut Bencher) {
            let secret = [0u8; 32];
            let info = [0u8; 32];
            let mut key = [0u8; 32];
            b.iter(|| {
                let (secret, info, key) = test::black_box((&secret, &info, &mut key));
                concat_kdf::derive_key_into::<$hash>(secret, info, key).unwrap();
                test::black_box(key);
            });
        }
    };
}

define_benchmark!(concat_kdf_sha224, Sha224);
define_benchmark!(concat_kdf_sha256, Sha256);
define_benchmark!(concat_kdf_sha512, Sha512);
