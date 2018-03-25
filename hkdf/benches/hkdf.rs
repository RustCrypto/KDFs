#[macro_use]
extern crate bencher;
extern crate hkdf;
extern crate sha2;

use bencher::Bencher;
use hkdf::Hkdf;
use sha2::Sha256;

fn sha256_10(b: &mut Bencher) {
    b.iter(|| Hkdf::<Sha256>::new(&[], &[]).derive(&[], 10));
    b.bytes = 10u64;
}

fn sha256_1k(b: &mut Bencher) {
    b.iter(|| Hkdf::<Sha256>::new(&[], &[]).derive(&[], 1024));
    b.bytes = 1024u64;
}

fn sha256_8k(b: &mut Bencher) {
    b.iter(|| Hkdf::<Sha256>::new(&[], &[]).derive(&[], 8000));
    b.bytes = 8000u64;
}

// note: SHA-256 output limit is 255*32=8160 bytes

benchmark_group!(benches,
                 sha256_10,
                 sha256_1k,
                 sha256_8k);
benchmark_main!(benches);
