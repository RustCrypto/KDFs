use criterion::{criterion_group, criterion_main, Criterion};
use sha2::{Sha224, Sha256, Sha512};

macro_rules! define_benchmark {
    ($function_name:ident, $digest_name:ident) => {
        fn $function_name(c: &mut Criterion) {
            c.bench_function(concat!("Concat KDF ", stringify!($digest_name)), |b| {
                b.iter(|| {
                    concat_kdf::derive_key_into::<$digest_name>(
                        &[0u8; 32],
                        &[0u8; 32],
                        &mut [0u8; 32],
                    )
                    .unwrap();
                })
            });
        }
    };
}

define_benchmark!(concat_kdf_sha224, Sha224);
define_benchmark!(concat_kdf_sha256, Sha256);
define_benchmark!(concat_kdf_sha512, Sha512);

criterion_group!(
    benches,
    concat_kdf_sha224,
    concat_kdf_sha256,
    concat_kdf_sha512
);
criterion_main!(benches);
