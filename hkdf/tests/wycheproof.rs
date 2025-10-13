use blobby::Blob4Iterator;
use hkdf::{GenericHkdf, HmacImpl};
use hmac::{Hmac, SimpleHmac};

fn test<H: HmacImpl>(data: &[u8]) {
    for (i, row) in Blob4Iterator::new(data).unwrap().enumerate() {
        let [ikm, salt, info, okm] = row.unwrap();

        let prk = GenericHkdf::<H>::new(Some(salt), ikm);
        let mut got_okm = vec![0; okm.len()];

        let mut err = None;
        if prk.expand(info, &mut got_okm).is_err() {
            err = Some("prk expand");
        }
        if got_okm != okm {
            err = Some("mismatch in okm");
        }

        if let Some(err_desc) = err {
            panic!(
                "\n\
                 Failed test №{i}: {err_desc}\n\
                 ikm:\t{ikm:?}\n\
                 salt:\t{salt:?}\n\
                 info:\t{info:?}\n\
                 okm:\t{okm:?}\n"
            );
        }
    }
}

macro_rules! new_test {
    ($name:ident, $test_name:expr, $hash:ty) => {
        #[test]
        fn $name() {
            let data = include_bytes!(concat!("data/", $test_name, ".blb"));
            test::<Hmac<$hash>>(data);
            test::<SimpleHmac<$hash>>(data);
        }
    };
}

new_test!(wycheproof_sha1, "wycheproof-sha1", sha1::Sha1);
new_test!(wycheproof_sha256, "wycheproof-sha256", sha2::Sha256);
new_test!(wycheproof_sha384, "wycheproof-sha384", sha2::Sha384);
new_test!(wycheproof_sha512, "wycheproof-sha512", sha2::Sha512);
