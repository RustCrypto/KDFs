# RustCrypto: KBKDF

[![crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
[![Build Status][build-image]][build-link]
![Apache2/MIT licensed][license-image]
![Rust Version][rustc-image]
[![Project Chat][chat-image]][chat-link]

Pure Rust implementation of the Key Based Key Derivation Function (KBKDF).
This function is described in section 4 of [NIST SP 800-108r1, Recommendation
for Key Derivation Using Pseudorandom Functions](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-108r1.pdf).

# Usage

The most common way to use KBKDF is as follows: you generate a shared secret with other party
(e.g. via Diffie-Hellman algorithm) and use key derivation function to derive a shared key.

```rust
use hex_literal::hex;
use hmac::Hmac;
use kbkdf::{Counter, Kbkdf, Params};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;
let counter = Counter::<HmacSha256, HmacSha256>::default();
let key = counter
    .derive(Params::builder(b"secret").with_label(b"label").build())
    .unwrap();
assert_eq!(
    key,
    hex!(
        "ff6a1e505e0f2546eae8f1e11ab95ff6"
        "47b78bb2182a835c7c1f8054ae7cfea5"
        "8182da6b978c411fa840326ebbe07bfc"
        "aaef01c090bb6f8e9c1da9dedf40bc3e"
    )
);
```

## Minimum Supported Rust Version

Rust **1.81** or higher.

Minimum supported Rust version can be changed in the future, but it will be
done with a minor version bump.

## SemVer Policy

- All on-by-default features of this library are covered by SemVer
- MSRV is considered exempt from SemVer as noted above

## License

Licensed under either of:

* [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)
* [MIT license](http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.

[crate-image]: https://img.shields.io/crates/v/kbkdf.svg
[crate-link]: https://crates.io/crates/kbkdf
[docs-image]: https://docs.rs/kbkdf/badge.svg
[docs-link]: https://docs.rs/kbkdf/
[build-image]: https://github.com/RustCrypto/KDFs/actions/workflows/kbkdf.yml/badge.svg
[build-link]: https://github.com/RustCrypto/KDFs/actions/workflows/kbkdf.yml
[license-image]: https://img.shields.io/badge/license-Apache2.0/MIT-blue.svg
[rustc-image]: https://img.shields.io/badge/rustc-1.81+-blue.svg
[chat-image]: https://img.shields.io/badge/zulip-join_chat-blue.svg
[chat-link]: https://rustcrypto.zulipchat.com/#narrow/stream/260043-KDFs

