use hkdf::Hkdf;
use sha1::Sha1;
use sha2::{Sha256, Sha384, Sha512};

/// Define test
macro_rules! new_test {
    ($name:ident, $test_name:expr, $hash:ty) => {
        #[test]
        fn $name() {
            use blobby::Blob4Iterator;

            fn run_test(ikm: &[u8], salt: &[u8], info: &[u8], okm: &[u8]) -> Option<&'static str> {
                let prk = Hkdf::<$hash>::new(Some(salt), ikm);
                let mut got_okm = vec![0; okm.len()];

                if prk.expand(info, &mut got_okm).is_err() {
                    return Some("prk expand");
                }
                if got_okm != okm {
                    return Some("mismatch in okm");
                }
                None
            }

            let data = include_bytes!(concat!("data/", $test_name, ".blb"));

            for (i, row) in Blob4Iterator::new(data).unwrap().enumerate() {
                let [ikm, salt, info, okm] = row.unwrap();
                if let Some(desc) = run_test(ikm, salt, info, okm) {
                    panic!(
                        "\n\
                         Failed test №{}: {}\n\
                         ikm:\t{:?}\n\
                         salt:\t{:?}\n\
                         info:\t{:?}\n\
                         okm:\t{:?}\n",
                        i, desc, ikm, salt, info, okm
                    );
                }
            }
        }
    };
}

new_test!(wycheproof_sha1, "wycheproof-sha1", Sha1);
new_test!(wycheproof_sha256, "wycheproof-sha256", Sha256);
new_test!(wycheproof_sha384, "wycheproof-sha384", Sha384);
new_test!(wycheproof_sha512, "wycheproof-sha512", Sha512);
