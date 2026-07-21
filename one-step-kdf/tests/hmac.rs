//! HMAC-based One-Step KDF tests.
#![allow(clippy::unwrap_used, reason = "tests")]

use digest::Digest;
use hex_literal::hex;
use hmac::{HmacReset, KeyInit};

use sha2::{Sha224, Sha256};

type HmacSha224 = HmacReset<Sha224>;
type HmacSha256 = HmacReset<Sha256>;

struct HmacFixture<'a> {
    secret: &'a [u8],
    salt: &'a [u8],
    other_info: &'a [u8],
    expected_key: &'a [u8],
}

fn test_hmac_key_derivation(fixtures: &[HmacFixture<'_>]) {
    for fixture in fixtures {
        let mut buf = [0u8; 256];

        for key_length in 1..=fixture.expected_key.len() {
            let key = &mut buf[..key_length];

            let aux = HmacSha256::new_from_slice(fixture.salt).unwrap();

            one_step_kdf::derive_key_into_with(aux, fixture.secret, fixture.other_info, key)
                .unwrap();

            assert_eq!(&fixture.expected_key[..key_length], key);
        }
    }
}

#[test]
fn test_input_output_hmac_sha256() {
    let fixtures = [HmacFixture {
        secret: &[0u8; 32],
        salt: &[0u8; 64],
        other_info: &[],
        expected_key: &hex!(
            "ceb496ba22edd29dfc5fa4e2d58abcc3"
            "0b49af2d76d754b54b5c02cf0a2c02dc"
        ),
    }];

    test_hmac_key_derivation(&fixtures);
}

#[test]
fn test_hmac_sha256_multiple_blocks() {
    let secret = [0u8; 32];
    let salt = [0u8; 64];
    let other_info = [];

    let aux = HmacSha256::new_from_slice(&salt).unwrap();
    let mut key = [0u8; 64];

    one_step_kdf::derive_key_into_with(aux, &secret, &other_info, &mut key).unwrap();

    assert_eq!(
        key,
        hex!(
            // HMAC-SHA256(salt, 00000001 || secret)
            "ceb496ba22edd29dfc5fa4e2d58abcc3"
            "0b49af2d76d754b54b5c02cf0a2c02dc"

            // HMAC-SHA256(salt, 00000002 || secret)
            "142cd755e28b5aae1958ac736f2c3190"
            "75137e3fe4d94f64c6fc99cb31e2ad53"
        )
    );
}

#[test]
fn nist_acvp_hmac_sha224() {
    // NIST ACVP sample vector for KDA OneStep SP 800-56C Rev. 2:
    // https://github.com/usnistgov/ACVP-Server/tree/master/
    // gen-val/json-files/KDA-OneStep-Sp800-56Cr2
    // Test group 16, test case 76.
    let salt = hex!(
        "00000000000000000000000000000000"
        "00000000000000000000000000000000"
        "00000000000000000000000000000000"
        "00000000000000000000000000000000"
    );
    let secret = hex!(
        "b41cb9f2a6fbe1ca42bf99c138e85437"
        "bdbd2e0ef64c1482d93fc8c6"
    );
    let fixed_info = hex!(
        // t
        "7bec348a2276f0e6a3c8a9950296d962"
        // uPartyInfo: partyId || ephemeralData
        "67f39f8c4d47cd8140f787478abdece0"
        "51f3b6a85db0763371211598f8c8e799"
        "cde4b1aa74f0613e08916b0a"
        // vPartyInfo: partyId
        "d69c15cc8ba1ac8a4ee7ba93ed2ab572"
        // L = 1024 bits, encoded as a big-endian 32-bit integer
        "00000400"
    );
    let expected = hex!(
        "5f850b63457b03c0ae065f31bf5f8849"
        "cdbb9376dd8e147bb8d2393d8db976dd"
        "01eae51c1d2a59a68f5bd760aca4adde"
        "19772028f3baeec07826f8cdb752f021"
        "7b100446b1650840d750a814dcad6999"
        "6c2f7caf34ff40115da23d386ad74866"
        "6a47ecc0bb72bfbcbc22505a3dbb1437"
        "d5518c7bc7aafe1026caa28524ebbfe2"
    );
    let aux = HmacSha224::new_from_slice(&salt).unwrap();
    let mut key = [0u8; 128];

    one_step_kdf::derive_key_into_with(aux, &secret, &fixed_info, &mut key).unwrap();

    assert_eq!(key, expected);
}

#[test]
fn generic_aux_matches_digest_api() {
    let secret = b"secret";
    let other_info = b"shared-info";

    let mut through_wrapper = [0u8; 64];
    let mut through_aux = [0u8; 64];

    one_step_kdf::derive_key_into::<Sha256>(secret, other_info, &mut through_wrapper).unwrap();

    one_step_kdf::derive_key_into_with(Sha256::new(), secret, other_info, &mut through_aux)
        .unwrap();

    assert_eq!(through_wrapper, through_aux);
}
