# [RustCrypto]: SP 800-108

[![crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
![Apache2/MIT licensed][license-image]
![Rust Version][rustc-image]
[![Project Chat][chat-image]][chat-link]
[![Build Status][build-image]][build-link]

Pure Rust implementation of the [NIST SP 800-108] KDFs generic over PRFs.

This crate currently supports Counter and Feedback KDFs and does not implement either the Double-Pipeline or KMAC-based KDFs.

# Usage

[NIST SP 800-108] describes multiple families of KDFs and ways to construct them.
This means that, unlike HKDF, there is not a specific "NIST SP 800-108 Counter KDF."
Instead, each user of this crate will need to define the specific KDF construction that meets their requirements.

**WARNING!** Properly defining the context is a *security-critical* decision. It is very easy to define an insecure KDF with an improper context. Generally, people should not be using this crate unless specifically required by compliance, standards, or protocols.

All SP 800-108 KDFs generate one block of output at a time using an underlying keyed PRF (pseudo-random function) such as HMAC or CMAC.
As input to the PRF is various context which may include constant labels, derivation specific non-secret values, and other values.
In order to generate outputs longer than the output length of the PRF, the KDF generates one block of data at a time from the PRF
and modifies the input to it so that each block is different.
This means that the context must contain some values which change from block to block.
The two ways of doing this are with a counter or feedback.
They can also be combined.

## Counter KDF

When used with a counter, one of the item in the context is a big-endian counter, starting at 1 and counting each block generated.
That way each block has a different input to the PRF and thus output.
You do this with [`ContextComponent::BeCounter`].

```rust
use sha2::Sha256;
use hmac::Hmac;
use aes::Aes128;
use cmac::Cmac;
use sp800_108::{ContextComponent, Kdf, KeyInit, NistSp800_108KDF};
use hex_literal::hex;

let ikm = hex!("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");

// For this example, we will have the additional data *before* the 32-bit counter.
// However, simply by reordering the elements, it could be placed after.
let context = [
    ContextComponent::NonSecret,
    ContextComponent::BeCounter(32)];
let kdf = NistSp800_108KDF::<Hmac<Sha256>>::new(&context).expect("KDF creation failed");

let mut key1 = [0u8; 16];
kdf.derive_key(&ikm, b"non-secret data 1", &mut key1).expect("Derivation failed");
println!("Derived key 1: {:?}", key1);

let mut key2 = [0u8; 32];
kdf.derive_key(&ikm, b"non-secret data 2", &mut key2).expect("Derivation failed");
println!("Derived key 2: {:?}", key2);

// Alternatively, the data can be encoded as fixed data directly in the context
let context = [
    ContextComponent::ConstantString("non-secret data 1"),
    ContextComponent::BeCounter(32)];
let kdf = NistSp800_108KDF::<Hmac<Sha256>>::new(&context).expect("KDF creation failed");

let mut key1_again = [0u8; 16];
kdf.derive_key(&ikm, &[] /* no input this time */, &mut key1_again).expect("Derivation failed");
assert_eq!(key1, key1_again);

// Some constructions require fixed data before and after the counter.
// Since kdf.derive_key() only takes in a single non-secret input, we must use a constant for one or both of them.
// This one is taken from a NIST test vector for use with CMAC-AES-128
let ikm = hex!("b6e04abd1651f8794d4326f4c684e631");
let context = [
    ContextComponent::ConstantBytes(&hex!(
        "93612f7256c46a3d856d3e951e32dbf15fe11159d0b389ad38d603850fee6d18d22031435ed36ee20da76745fbea4b10fe1e")), 
    ContextComponent::BeCounter(8),
    ContextComponent::ConstantBytes(&hex!("99322aae605a5f01e32b"))];
let mut key3 = [0u8; 16];
let kdf = NistSp800_108KDF::<Cmac<Aes128>>::new(&context).expect("KDF creation failed");
kdf.derive_key(&ikm, &[], &mut key3).expect("Derivation failed");
assert_eq!(key3, hex!("dcb1db87a68762c6b3354779fa590bef"));
```

## Feedback KDF

Another way of modifying the input to the PRF for each block is to feedback the value of the prior block into the input for the next block.
You do this with You do this with [`ContextComponent::Feedback`] which takes in an `iv` (which may be empty).
The `iv` is provided as input to the first block.

```rust
use sha2::Sha256;
use hmac::Hmac;
use aes::Aes128;
use cmac::Cmac;
use sp800_108::{ContextComponent, Kdf, KeyInit, NistSp800_108KDF};
use hex_literal::hex;

let ikm = hex!("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");

let context = [
    ContextComponent::ConstantString("non-secret data"),
    ContextComponent::Feedback(&[]),// empty IV
];
let kdf = NistSp800_108KDF::<Hmac<Sha256>>::new(&context).expect("KDF creation failed");

let mut key1 = [64];
kdf.derive_key(&ikm, &[], &mut key1).expect("Derivation failed");
println!("Derived key 1: {:?}", key1);

// With an IV we'll get a different output
let context = [
    ContextComponent::ConstantString("non-secret data 1"),
    ContextComponent::Feedback(b"YellowSubmarine"), // Non-empty IV
];
let kdf = NistSp800_108KDF::<Hmac<Sha256>>::new(&context).expect("KDF creation failed");

let mut key2 = [64];
kdf.derive_key(&ikm, &[], &mut key2).expect("Derivation failed");
println!("Derived key 2: {:?}", key2);
assert_ne!(key1, key2);

// Finally, some constructions have both counters and feedback
let context = [
    ContextComponent::ConstantString("non-secret data"),
    ContextComponent::BeCounter(16),
    ContextComponent::NonSecret,
    ContextComponent::Feedback(&[]),// empty IV
];

let kdf = NistSp800_108KDF::<Hmac<Sha256>>::new(&context).expect("KDF creation failed");

let mut key3 = [64];
kdf.derive_key(&ikm, &[], &mut key3).expect("Derivation failed");
println!("Derived key 3: {:?}", key3);
```

## License

Licensed under either of:

* [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)
* [MIT license](http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.

[//]: # (badges)

[crate-image]: https://img.shields.io/crates/v/sp800-108.svg
[crate-link]: https://crates.io/crates/sp800-108
[docs-image]: https://docs.rs/sp800-108/badge.svg
[docs-link]: https://docs.rs/sp800-108/
[license-image]: https://img.shields.io/badge/license-Apache2.0/MIT-blue.svg
[rustc-image]: https://img.shields.io/badge/rustc-1.85+-blue.svg
[chat-image]: https://img.shields.io/badge/zulip-join_chat-blue.svg
[chat-link]: https://rustcrypto.zulipchat.com/#narrow/stream/260043-KDFs
[build-image]: https://github.com/RustCrypto/KDFs/workflows/sp800-108/badge.svg?branch=master&event=push
[build-link]: https://github.com/RustCrypto/KDFs/actions?query=workflow:sp800-108

[//]: # (links)

[RustCrypto]: https://github.com/RustCrypto
[NIST SP 800-108]: https://csrc.nist.gov/pubs/sp/800/108/r1/upd1/final