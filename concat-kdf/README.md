# RustCrypto: Concat KDF

[![crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
![Apache2/MIT licensed][license-image]
![Rust Version][rustc-image]
[![Project Chat][chat-image]][chat-link]
[![Build Status][build-image]][build-link]

Pure Rust implementation of the Concatenation Key Derivation Function (Concat KDF) generic over hash function. 
This function is described in the section 5.8.1 of [NIST SP 800-56A, Recommendation for Pair-Wise Key Establishment
Schemes Using Discrete Logarithm Cryptography](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-56ar.pdf).

# Usage

The most common way to use Concat KDF is as follows: you generate a shared secret with other party
(e.g. via Diffie-Hellman algorithm) and use key derivation function to derive a shared key.

```rust
use hex_literal::hex;
use sha2::Sha256;

let mut key = [0u8; 16];
concat_kdf::derive_key_into::<Sha256>(b"secret", b"shared-info", &mut key).unwrap();
assert_eq!(key, hex!("960db2c549ab16d71a7b008e005c2bdc"));
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

[crate-image]: https://img.shields.io/crates/v/concat-kdf.svg
[crate-link]: https://crates.io/crates/concat-kdf
[docs-image]: https://docs.rs/concat-kdf/badge.svg
[docs-link]: https://docs.rs/concat-kdf/
[license-image]: https://img.shields.io/badge/license-Apache2.0/MIT-blue.svg
[rustc-image]: https://img.shields.io/badge/rustc-1.85+-blue.svg
[chat-image]: https://img.shields.io/badge/zulip-join_chat-blue.svg
[chat-link]: https://rustcrypto.zulipchat.com/#narrow/stream/260043-KDFs
[build-image]: https://github.com/RustCrypto/KDFs/workflows/concat-kdf/badge.svg?branch=master&event=push
[build-link]: https://github.com/RustCrypto/KDFs/actions?query=workflow:concat-kdf
