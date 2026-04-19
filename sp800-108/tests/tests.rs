//! CAVP test vectors.

use core::fmt::Debug;

use aes::{Aes128, Aes192, Aes256};
use cmac::Cmac;
use digest::{KeyInit, FixedOutput};
use hmac::Hmac;
use kdf::Kdf;
use sha1::Sha1;
use sha2::{Sha224, Sha256, Sha384, Sha512};
use sp800_108::{ContextComponent, NistSp800_108KDF};

#[derive(Copy, Clone)]
struct TestVector {
    ctr_location: &'static [u8],
    rlen: &'static [u8],
    key: &'static [u8],
    fixed_input_data: &'static [u8],
    data_before_ctr: &'static [u8],
    data_after_ctr: &'static [u8],
    okm: &'static [u8],
}

impl Debug for TestVector {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        writeln!(f, "TestVector {{")?;
        writeln!(f, "    ctr_location: \"{}\"", String::from_utf8_lossy(self.ctr_location).to_string())?;
        writeln!(f, "    rlen: \"{}\"", String::from_utf8_lossy(self.rlen).to_string())?;
        writeln!(f, "    key: {}", hex::encode(self.key))?;
        writeln!(f, "    fixed_input_data: {}", hex::encode(self.fixed_input_data))?;
        writeln!(f, "    data_before_ctr: {}", hex::encode(self.data_before_ctr))?;
        writeln!(f, "    data_after_ctr: {}", hex::encode(self.data_after_ctr))?;
        writeln!(f, "    okm: {}", hex::encode(self.okm))?;
        writeln!(f, "}}")
    }
}

/// Tests each test vector both encoding the fixed data as a constant value in the context
/// and as non-secret data passed in by the caller.
fn test_cavp<P>(test_vectors: &[TestVector])
where P: FixedOutput + KeyInit + Clone {
    let mut buf = [0u8; 1 << 14];
    for (i, tv) in test_vectors.iter().enumerate() {
        // rlen takes the form of <NUM>_BITS. Example: "8_BITS"
        let rlen = String::from_utf8_lossy(tv.rlen).to_string();
        let rlen = rlen.split('_').next().expect("CAVP data incorrectly formatted").trim();
        let rlen = rlen.parse::<usize>();
        let rlen = rlen.expect("CAVP data incorrectly formatted");
        let ctr_location = String::from_utf8_lossy(tv.ctr_location).to_string();
        let okm_dst = &mut buf[..tv.okm.len()];
        let mut err = None;
        match ctr_location.as_str() {
            "MIDDLE_FIXED" => {
                // Test with no input, just constants
                let context = [
                    ContextComponent::ConstantBytes(tv.data_before_ctr),
                    ContextComponent::BeCtr(rlen),
                    ContextComponent::ConstantBytes(tv.data_after_ctr)
                ];
                let kdf = NistSp800_108KDF::<P>::new(&context);
                assert!(kdf.is_ok(), "Failed test #{i}: (Const+Const) Creating KDF\nTest vector:\t{tv:#?}");
                let kdf = kdf.expect("Already verified this is ok");
                okm_dst.fill(0);
                if kdf.derive_key(tv.key, &[], okm_dst).is_err() {
                    err = Some("derive_key");
                }
                if okm_dst != tv.okm {
                    err = Some("mismatch in okm");
                }
                if let Some(err_desc) = err {
                    panic!("Failed test #{i}: (Const+Const) {err_desc}\nTest vector:\t{tv:#?}");
                }
                // Test where first value is input
                let context = [
                    ContextComponent::NonSecret,
                    ContextComponent::BeCtr(rlen),
                    ContextComponent::ConstantBytes(tv.data_after_ctr)
                ];
                let kdf = NistSp800_108KDF::<P>::new(&context);
                assert!(kdf.is_ok(), "Failed test #{i}: (Input+Const) Creating KDF\nTest vector:\t{tv:#?}");
                let kdf = kdf.expect("Already verified this is ok");
                okm_dst.fill(0);
                if kdf.derive_key(tv.key, tv.data_before_ctr, okm_dst).is_err() {
                    err = Some("derive_key");
                }
                if okm_dst != tv.okm {
                    err = Some("mismatch in okm");
                }
                if let Some(err_desc) = err {
                    panic!("Failed test #{i}: (Input+Const) {err_desc}\nTest vector:\t{tv:#?}");
                }
                // Test where second value is input
                let context = [
                    ContextComponent::ConstantBytes(tv.data_before_ctr),
                    ContextComponent::BeCtr(rlen),
                    ContextComponent::NonSecret
                ];
                let kdf = NistSp800_108KDF::<P>::new(&context);
                assert!(kdf.is_ok(), "Failed test #{i}: (Const+Input) Creating KDF\nTest vector:\t{tv:#?}");
                let kdf = kdf.expect("Already verified this is ok");
                okm_dst.fill(0);
                if kdf.derive_key(tv.key, tv.data_after_ctr, okm_dst).is_err() {
                    err = Some("derive_key");
                }
                if okm_dst != tv.okm {
                    err = Some("mismatch in okm");
                }
                if let Some(err_desc) = err {
                    panic!("Failed test #{i}: (Const+Input) {err_desc}\nTest vector:\t{tv:#?}");
                }
            },
            "BEFORE_FIXED" => {
                // Test with no input, just constants
                let context = [
                    ContextComponent::BeCtr(rlen),
                    ContextComponent::ConstantBytes(tv.fixed_input_data),
                ];
                let kdf = NistSp800_108KDF::<P>::new(&context);
                assert!(kdf.is_ok(), "Failed test #{i}: (Const) Creating KDF\nTest vector:\t{tv:#?}");
                let kdf = kdf.expect("Already verified this is ok");
                okm_dst.fill(0);
                if kdf.derive_key(tv.key, &[], okm_dst).is_err() {
                    err = Some("derive_key");
                }
                if okm_dst != tv.okm {
                    err = Some("mismatch in okm");
                }
                if let Some(err_desc) = err {
                    panic!("Failed test #{i}: (Const) {err_desc}\nTest vector:\t{tv:#?}");
                }
                // Test where first value is input
                let context = [
                    ContextComponent::BeCtr(rlen),
                    ContextComponent::NonSecret,
                ];
                let kdf = NistSp800_108KDF::<P>::new(&context);
                assert!(kdf.is_ok(), "Failed test #{i}: (Input) Creating KDF\nTest vector:\t{tv:#?}");
                let kdf = kdf.expect("Already verified this is ok");
                okm_dst.fill(0);
                if kdf.derive_key(tv.key, tv.fixed_input_data, okm_dst).is_err() {
                    err = Some("derive_key");
                }
                if okm_dst != tv.okm {
                    err = Some("mismatch in okm");
                }
                if let Some(err_desc) = err {
                    panic!("Failed test #{i}: (Input) {err_desc}\nTest vector:\t{tv:#?}");
                }
            }
            "AFTER_FIXED" => {
                // Test with no input, just constants
                let context = [
                    ContextComponent::ConstantBytes(tv.fixed_input_data),
                    ContextComponent::BeCtr(rlen),
                ];
                let kdf = NistSp800_108KDF::<P>::new(&context);
                assert!(kdf.is_ok(), "Failed test #{i}: (Const) Creating KDF\nTest vector:\t{tv:#?}");
                let kdf = kdf.expect("Already verified this is ok");
                okm_dst.fill(0);
                if kdf.derive_key(tv.key, &[], okm_dst).is_err() {
                    err = Some("derive_key");
                }
                if okm_dst != tv.okm {
                    err = Some("mismatch in okm");
                }
                if let Some(err_desc) = err {
                    panic!("Failed test #{i}: (Const) {err_desc}\nTest vector:\t{tv:#?}");
                }
                // Test where first value is input
                let context = [
                    ContextComponent::NonSecret,
                    ContextComponent::BeCtr(rlen),
                ];
                let kdf = NistSp800_108KDF::<P>::new(&context);
                if kdf.is_err() {
                    panic!("Failed test #{i}: (Input) Creating KDF\nTest vector:\t{tv:#?}");
                }
                let kdf = kdf.expect("Already verified this is ok");
                okm_dst.fill(0);
                if kdf.derive_key(tv.key, tv.fixed_input_data, okm_dst).is_err() {
                    err = Some("derive_key");
                }
                if okm_dst != tv.okm {
                    err = Some("mismatch in okm");
                }
                if let Some(err_desc) = err {
                    panic!("Failed test #{i}: (Input) {err_desc}\nTest vector:\t{tv:#?}");
                }
            }
            _ => panic!("Unsupport counter location: {}", ctr_location),
        };
    }
}

macro_rules! new_test {
    ($name:ident, $prf:ty) => {
        #[test]
        fn $name() {
            blobby::parse_into_structs!(
                include_bytes!(concat!("data/", stringify!($name), ".blb"));
                static TEST_VECTORS: &[TestVector { ctr_location, rlen, key, fixed_input_data, data_before_ctr, data_after_ctr, okm }];
            );

            test_cavp::<$prf>(TEST_VECTORS);
        }
    };
}

// All tests from https://csrc.nist.gov/Projects/Cryptographic-Algorithm-Validation-Program/Key-Derivation

// KDF in Counter Mode Test Vectors
new_test!(hmac_sha1, Hmac<Sha1>);
new_test!(hmac_sha224, Hmac<Sha224>);
new_test!(hmac_sha256, Hmac<Sha256>);
new_test!(hmac_sha384, Hmac<Sha384>);
new_test!(hmac_sha512, Hmac<Sha512>);

new_test!(cmac_aes128, Cmac<Aes128>);
new_test!(cmac_aes192, Cmac<Aes192>);
new_test!(cmac_aes256, Cmac<Aes256>);

// TODO: Test Feedback
// TODO: Test K0
// TODO: Test BeLength