//! CAVP test vectors.

use core::fmt::Debug;

use aes::{Aes128, Aes192, Aes256};
use cmac::Cmac;
use digest::{FixedOutput, KeyInit};
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
    iv: &'static [u8],
    fixed_input_data: &'static [u8],
    data_before_ctr: &'static [u8],
    data_after_ctr: &'static [u8],
    okm: &'static [u8],
}

impl Debug for TestVector {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        writeln!(f, "TestVector {{")?;
        writeln!(
            f,
            "    ctr_location: \"{}\"",
            String::from_utf8_lossy(self.ctr_location).to_string()
        )?;
        writeln!(
            f,
            "    rlen: \"{}\"",
            String::from_utf8_lossy(self.rlen).to_string()
        )?;
        writeln!(f, "    key: {}", hex::encode(self.key))?;
        writeln!(f, "    iv: {}", hex::encode(self.iv))?;
        writeln!(
            f,
            "    fixed_input_data: {}",
            hex::encode(self.fixed_input_data)
        )?;
        writeln!(
            f,
            "    data_before_ctr: {}",
            hex::encode(self.data_before_ctr)
        )?;
        writeln!(
            f,
            "    data_after_ctr: {}",
            hex::encode(self.data_after_ctr)
        )?;
        writeln!(f, "    okm: {}", hex::encode(self.okm))?;
        writeln!(f, "}}")
    }
}

fn test_cases<P>(cases: &[(Vec<ContextComponent>, &[u8])], i: usize, tv: &TestVector)
where
    P: FixedOutput + KeyInit + Clone,
{
    let mut okm_dst = vec![0u8; tv.okm.len()];
    for c in cases {
        let context = &c.0;
        let input = c.1;
        okm_dst.fill(0);
        let kdf = NistSp800_108KDF::<P>::new(&c.0);
        assert!(
            kdf.is_ok(),
            "Failed test #{i}: {context:?} Creating KDF\nTest vector:\t{tv:#?}"
        );
        let kdf = kdf.expect("Already verified this is ok");

        assert!(
            kdf.derive_key(tv.key, input, &mut okm_dst).is_ok(),
            "Failed test #{i}: {context:?} derive_key\nTest vector:\t{tv:#?}"
        );
        assert_eq!(
            &okm_dst, tv.okm,
            "Failed test #{i}: {context:?} mismatch in okm\nTest vector:\t{tv:#?}"
        );
    }
}

fn parse_rlen(rlen: &[u8]) -> u8 {
    String::from_utf8_lossy(rlen)
        .split('_')
        .next()
        .expect("CAVP data incorrectly formatted")
        .trim()
        .parse::<u8>()
        .expect("CAVP data incorrectly formatted")
}

fn test_ctr<P>(test_vectors: &[TestVector])
where
    P: FixedOutput + KeyInit + Clone,
{
    for (i, tv) in test_vectors.iter().enumerate() {
        // rlen takes the form of <NUM>_BITS. Example: "8_BITS"
        let rlen = parse_rlen(tv.rlen);
        let ctr_location = String::from_utf8_lossy(tv.ctr_location).to_string();
        match ctr_location.as_str() {
            "MIDDLE_FIXED" => {
                test_cases::<P>(
                    &[
                        (
                            vec![
                                ContextComponent::ConstantBytes(tv.data_before_ctr),
                                ContextComponent::BeCounter(rlen),
                                ContextComponent::ConstantBytes(tv.data_after_ctr),
                            ],
                            &[],
                        ),
                        (
                            vec![
                                ContextComponent::NonSecret,
                                ContextComponent::BeCounter(rlen),
                                ContextComponent::ConstantBytes(tv.data_after_ctr),
                            ],
                            tv.data_before_ctr,
                        ),
                        (
                            vec![
                                ContextComponent::ConstantBytes(tv.data_before_ctr),
                                ContextComponent::BeCounter(rlen),
                                ContextComponent::NonSecret,
                            ],
                            tv.data_after_ctr,
                        ),
                    ],
                    i,
                    tv,
                );
            }
            "BEFORE_FIXED" => {
                test_cases::<P>(
                    &[
                        (
                            vec![
                                ContextComponent::BeCounter(rlen),
                                ContextComponent::ConstantBytes(tv.fixed_input_data),
                            ],
                            &[],
                        ),
                        (
                            vec![
                                ContextComponent::BeCounter(rlen),
                                ContextComponent::NonSecret,
                            ],
                            tv.fixed_input_data,
                        ),
                    ],
                    i,
                    tv,
                );
            }
            "AFTER_FIXED" => {
                test_cases::<P>(
                    &[
                        (
                            vec![
                                ContextComponent::ConstantBytes(tv.fixed_input_data),
                                ContextComponent::BeCounter(rlen),
                            ],
                            &[],
                        ),
                        (
                            vec![
                                ContextComponent::NonSecret,
                                ContextComponent::BeCounter(rlen),
                            ],
                            tv.fixed_input_data,
                        ),
                    ],
                    i,
                    tv,
                );
            }
            _ => panic!("Unsupported counter location: {}", ctr_location),
        };
    }
}

fn test_feedback<P>(test_vectors: &[TestVector])
where
    P: FixedOutput + KeyInit + Clone,
{
    for (i, tv) in test_vectors.iter().enumerate() {
        test_cases::<P>(
            &[
                (
                    vec![
                        ContextComponent::Feedback(tv.iv),
                        ContextComponent::ConstantBytes(tv.fixed_input_data),
                    ],
                    &[],
                ),
                (
                    vec![
                        ContextComponent::Feedback(tv.iv),
                        ContextComponent::NonSecret,
                    ],
                    tv.fixed_input_data,
                ),
            ],
            i,
            tv,
        );
    }
}

fn test_feedback_ctr<P>(test_vectors: &[TestVector])
where
    P: FixedOutput + KeyInit + Clone,
{
    for (i, tv) in test_vectors.iter().enumerate() {
        // rlen takes the form of <NUM>_BITS. Example: "8_BITS"
        let rlen = parse_rlen(tv.rlen);
        let ctr_location = String::from_utf8_lossy(tv.ctr_location).to_string();
        let cases: &mut [(Vec<ContextComponent>, &[u8])] = &mut [
            (
                vec![
                    ContextComponent::Feedback(tv.iv),
                    ContextComponent::ConstantBytes(tv.fixed_input_data),
                ],
                &[],
            ),
            (
                vec![
                    ContextComponent::Feedback(tv.iv),
                    ContextComponent::NonSecret,
                ],
                tv.fixed_input_data,
            ),
        ];
        let ctr_idx = match ctr_location.as_str() {
            "BEFORE_ITER" => 0,
            "AFTER_ITER" => 1,
            "AFTER_FIXED" => 2,
            _ => panic!("Unsupported counter location: {}", ctr_location),
        };
        for c in cases.iter_mut() {
            c.0.insert(ctr_idx, ContextComponent::BeCounter(rlen));
        }
        test_cases::<P>(cases, i, tv);
    }
}

macro_rules! new_test {
    ($name:ident, $prf:ty, $test:ident) => {
        #[test]
        fn $name() {
            blobby::parse_into_structs!(
                include_bytes!(concat!("data/", stringify!($name), ".blb"));
                static TEST_VECTORS: &[TestVector { ctr_location, rlen, key, iv, fixed_input_data, data_before_ctr, data_after_ctr, okm }];
            );

            $test::<$prf>(TEST_VECTORS);
        }
    };
}

// All tests from https://csrc.nist.gov/Projects/Cryptographic-Algorithm-Validation-Program/Key-Derivation

// KDF in Counter Mode Test Vectors
new_test!(ctr_hmac_sha1, Hmac<Sha1>, test_ctr);
new_test!(ctr_hmac_sha224, Hmac<Sha224>, test_ctr);
new_test!(ctr_hmac_sha256, Hmac<Sha256>, test_ctr);
new_test!(ctr_hmac_sha384, Hmac<Sha384>, test_ctr);
new_test!(ctr_hmac_sha512, Hmac<Sha512>, test_ctr);

new_test!(ctr_cmac_aes128, Cmac<Aes128>, test_ctr);
new_test!(ctr_cmac_aes192, Cmac<Aes192>, test_ctr);
new_test!(ctr_cmac_aes256, Cmac<Aes256>, test_ctr);

// KDF in Feedback Mode Test Vectors where no counter is used
new_test!(feedback_hmac_sha1, Hmac<Sha1>, test_feedback);
new_test!(feedback_hmac_sha224, Hmac<Sha224>, test_feedback);
new_test!(feedback_hmac_sha256, Hmac<Sha256>, test_feedback);
new_test!(feedback_hmac_sha384, Hmac<Sha384>, test_feedback);
new_test!(feedback_hmac_sha512, Hmac<Sha512>, test_feedback);

new_test!(feedback_cmac_aes128, Cmac<Aes128>, test_feedback);
new_test!(feedback_cmac_aes192, Cmac<Aes192>, test_feedback);
new_test!(feedback_cmac_aes256, Cmac<Aes256>, test_feedback);

// KDF in Feedback Mode Test Vectors where zero length IV is allowed
new_test!(feedback_ctr_hmac_sha1, Hmac<Sha1>, test_feedback_ctr);
new_test!(feedback_ctr_hmac_sha224, Hmac<Sha224>, test_feedback_ctr);
new_test!(feedback_ctr_hmac_sha256, Hmac<Sha256>, test_feedback_ctr);
new_test!(feedback_ctr_hmac_sha384, Hmac<Sha384>, test_feedback_ctr);
new_test!(feedback_ctr_hmac_sha512, Hmac<Sha512>, test_feedback_ctr);

new_test!(feedback_ctr_cmac_aes128, Cmac<Aes128>, test_feedback_ctr);
new_test!(feedback_ctr_cmac_aes192, Cmac<Aes192>, test_feedback_ctr);
new_test!(feedback_ctr_cmac_aes256, Cmac<Aes256>, test_feedback_ctr);
