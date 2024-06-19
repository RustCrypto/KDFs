use blobby::Blob4Iterator;
use hkdf::{Hkdf, HmacImpl};
use hmac::{Hmac, SimpleHmac};
use sha1::Sha1;
use sha2::{digest::OutputSizeUser, Sha256, Sha384, Sha512};

fn test<H: OutputSizeUser, I: HmacImpl<H>>(data: &[u8]) {
    for (i, row) in Blob4Iterator::new(data).unwrap().enumerate() {
        let [ikm, salt, info, okm] = row.unwrap();

        let prk = Hkdf::<H, I>::new(Some(salt), ikm);
        let mut got_okm = vec![0; okm.len()];

        let mut err = None;
        if prk.expand(info, &mut got_okm).is_err() {
            err = Some("prk expand");
        }
        if got_okm != okm {
            err = Some("mismatch in okm");
        }

        if let Some(desc) = err {
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

/// Define test
macro_rules! new_test {
    ($name:ident, $test_name:expr, $hash:ty) => {
        #[test]
        fn $name() {
            let data = include_bytes!(concat!("data/", $test_name, ".blb"));
            test::<$hash, Hmac<$hash>>(data);
            test::<$hash, SimpleHmac<$hash>>(data);
        }
    };
}

new_test!(wycheproof_sha1, "wycheproof-sha1", Sha1);
new_test!(wycheproof_sha256, "wycheproof-sha256", Sha256);
new_test!(wycheproof_sha384, "wycheproof-sha384", Sha384);
new_test!(wycheproof_sha512, "wycheproof-sha512", Sha512);
