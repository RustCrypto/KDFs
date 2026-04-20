//! Tests covering specific edge-cases not necessarily covered by the CAVP tests vectors

use digest::Update;
use hmac::{Hmac, KeyInit, Mac};
use kdf::Kdf;
use sha2::Sha256;
use sp800_108::{ContextComponent, NistSp800_108KDF};

/// Tests that we properly handle the `K0` and `ConstantString` components
#[test]
fn k0_test() {
    let key = b"1234567890abcdef";
    let label = "Label";
    let ctr_0 = [0u8; 4];

    let mut hmac = Hmac::<Sha256>::new_from_slice(key).expect("Could not construct hmac");
    Update::update(&mut hmac, &ctr_0);
    Update::update(&mut hmac, label.as_bytes());
    let k0 = hmac.finalize().as_bytes().to_vec();

    let ctr_1 = [0u8, 0u8, 0u8, 1u8];

    let mut hmac = Hmac::<Sha256>::new_from_slice(key).expect("Could not construct hmac");
    Update::update(&mut hmac, &ctr_1);
    Update::update(&mut hmac, label.as_bytes());
    Update::update(&mut hmac, &k0);
    let expected = hmac.finalize().as_bytes().to_vec();

    // Use the KDF now
    let context = [
        ContextComponent::BeCtr(32),
        ContextComponent::ConstantString(label),
        ContextComponent::K0,
    ];
    let kdf = NistSp800_108KDF::<Hmac<Sha256>>::new(&context).expect("Could not construct KDF");
    let mut actual = vec![0u8; expected.len()];
    kdf.derive_key(key, &[], &mut actual)
        .expect("Could not derive key");
    assert_eq!(actual, expected);
}

// TODO: Fail if non_secret but no use
