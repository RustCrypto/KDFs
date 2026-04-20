//! Tests covering specific edge-cases not necessarily covered by the CAVP tests vectors

use digest::{OutputSizeUser, Update};
use hmac::{Hmac, KeyInit, Mac};
use kdf::Kdf;
use sha1::Sha1;
use sha2::Sha256;
use sp800_108::{ContextComponent, NistSp800_108KDF};

/// Tests that we properly handle the `K0` and `ConstantString` components
/// See section 4.1.
#[test]
fn k0_test() {
    let key = b"1234567890abcdef";
    let label = "Label";

    let mut hmac = Hmac::<Sha256>::new_from_slice(key).expect("Could not construct hmac");
    // Counter is omitted
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
        ContextComponent::BeCounter(32),
        ContextComponent::ConstantString(label),
        ContextComponent::K0,
    ];
    let kdf = NistSp800_108KDF::<Hmac<Sha256>>::new(&context).expect("Could not construct KDF");
    let mut actual = vec![0u8; expected.len()];
    kdf.derive_key(key, &[], &mut actual)
        .expect("Could not derive key");
    assert_eq!(actual, expected);
}

/// Tests that we reject outputs where the counter would roll over
#[test]
fn length_limit() {
    let h_len = Sha1::output_size();
    let context = [ContextComponent::BeCounter(8)]; // 8 bits, max 255
    let kdf = NistSp800_108KDF::<Hmac<Sha1>>::new(&context).expect("Could not create KDF");
    let key = b"1234567890abcdef";

    // Largest possible output
    let mut out = vec![0u8; h_len * 255];
    assert!(
        kdf.derive_key(key, &[], &mut out).is_ok(),
        "Unable to derive key of acceptable length"
    );

    // Too big
    out.resize(out.len() + 1, 0);
    assert!(
        kdf.derive_key(key, &[], &mut out).is_err(),
        "Did not reject overlength output"
    );
}

/// Tests that we reject if you attempt to pass non-secret data as input but the context doesn't use it
#[test]
fn non_secret_input_used() {
    let key = b"1234567890abcdef";
    let ignored_input = "Ignored input";

    let context = [ContextComponent::BeCounter(32)];
    let kdf = NistSp800_108KDF::<Hmac<Sha256>>::new(&context).expect("Could not construct KDF");

    let mut out = [0u8; 16];
    assert!(
        kdf.derive_key(key, ignored_input.as_bytes(), &mut out)
            .is_err(),
        "Did not reject ignored input"
    );
}

/// Require at least one non-null element
#[test]
fn non_null_ctx() {
    assert!(
        NistSp800_108KDF::<Hmac<Sha256>>::new(&[]).is_err(),
        "Constructed KDF with empty context"
    );

    assert!(
        NistSp800_108KDF::<Hmac<Sha256>>::new(&[ContextComponent::Null]).is_err(),
        "Constructed KDF with only null context"
    );
}

/// Requires that all non-null `ContextComponent` values are before any `Null` ones.
#[test]
fn non_null_ctx_at_start() {
    // Base case
    let context = [ContextComponent::BeCounter(32)];
    assert!(
        NistSp800_108KDF::<Hmac<Sha256>>::new(&context).is_ok(),
        "Could not construct KDF"
    );

    // Identical to base
    let context = [ContextComponent::BeCounter(32), ContextComponent::Null];
    assert!(
        NistSp800_108KDF::<Hmac<Sha256>>::new(&context).is_ok(),
        "Could not construct KDF"
    );

    // Only a single non-null
    let context = [ContextComponent::Null, ContextComponent::BeCounter(32)];
    assert!(
        NistSp800_108KDF::<Hmac<Sha256>>::new(&context).is_err(),
        "Did not reject"
    );

    // Null in between
    let context = [
        ContextComponent::ConstantString("Some value"),
        ContextComponent::Null,
        ContextComponent::BeCounter(32),
    ];
    assert!(
        NistSp800_108KDF::<Hmac<Sha256>>::new(&context).is_err(),
        "Did not reject"
    );
}

/// Test that BeLength is properly handled
#[test]
fn be_length() {
    let key = b"1234567890abcdef";
    let label = "Label";
    let context = [
        ContextComponent::ConstantString(label),
        ContextComponent::BeLength(8),
    ];
    let kdf = NistSp800_108KDF::<Hmac<Sha256>>::new(&context).expect("Could not create KDF");

    // Length 16
    let length = [16u8];
    let mut hmac = Hmac::<Sha256>::new_from_slice(key).expect("Could not construct hmac");
    Update::update(&mut hmac, label.as_bytes());
    Update::update(&mut hmac, &length);
    let mut expected = hmac.finalize().as_bytes().to_vec();
    expected.truncate(16);
    let mut actual = [0u8; 16];
    assert!(
        kdf.derive_key(key, &[], &mut actual).is_ok(),
        "Could not derive key"
    );
    assert_eq!(
        &actual[..],
        &expected,
        "Derived keys are different for length 16"
    );

    // Length 32
    let length = [32u8];
    let mut hmac = Hmac::<Sha256>::new_from_slice(key).expect("Could not construct hmac");
    Update::update(&mut hmac, label.as_bytes());
    Update::update(&mut hmac, &length);
    let expected = hmac.finalize().as_bytes().to_vec();
    let mut actual = [0u8; 32];
    assert!(
        kdf.derive_key(key, &[], &mut actual).is_ok(),
        "Could not derive key"
    );
    assert_eq!(
        &actual[..],
        &expected,
        "Derived keys are different for length 16"
    );
}
