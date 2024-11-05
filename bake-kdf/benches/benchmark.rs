#![feature(test)]
extern crate test;

use bake_kdf::bake_kdf;
use test::Bencher;

#[bench]
fn bake_kdf_benchmark(b: &mut Bencher) {
    let secret = [0u8; 32];
    let iv = [0u8; 64];
    let c = 0u128;
    b.iter(|| {
        let (secret, iv, c) = test::black_box((&secret, &iv, c));
        test::black_box(bake_kdf(secret, iv, c));
    });
}
