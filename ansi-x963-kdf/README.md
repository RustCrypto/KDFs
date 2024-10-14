# RustCrypto: ANSI X9.63 Key Derivation Function

[![crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
![Apache2/MIT licensed][license-image]
![Rust Version][rustc-image]
[![Project Chat][chat-image]][chat-link]
[![Build Status][build-image]][build-link]

Pure Rust implementation of the ANSI X9.63 Key Derivation Function (ANSI-X9.63-KDF) generic over hash function. 
This function is described in the section 3.6.1 of [SEC 1: Elliptic Curve Cryptography](http://www.secg.org/sec1-v2.pdf).

# Usage

The most common way to use ANSI-X9.63-KDF is as follows: you generate a shared secret with other
party (e.g. via Diffie-Hellman algorithm)  and use key derivation function to derive a shared key.

```rust
use hex_literal::hex;
use sha2::Sha256;

let mut key = [0u8; 16];
ansi_x963_kdf::derive_key_into::<Sha256>(b"secret", b"shared-info", &mut key).unwrap();
assert_eq!(key, hex!("8dbb1d50bcc7fc782abc9db5c64a2826"));
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

[crate-image]: https://img.shields.io/crates/v/ansi-x963-kdf.svg
[crate-link]: https://crates.io/crates/ansi-x963-kdf
[docs-image]: https://docs.rs/ansi-x963-kdf/badge.svg
[docs-link]: https://docs.rs/ansi-x963-kdf/
[license-image]: https://img.shields.io/badge/license-Apache2.0/MIT-blue.svg
[rustc-image]: https://img.shields.io/badge/rustc-1.81+-blue.svg
[chat-image]: https://img.shields.io/badge/zulip-join_chat-blue.svg
[chat-link]: https://rustcrypto.zulipchat.com/#narrow/stream/260043-KDFs
[build-image]: https://github.com/RustCrypto/KDFs/workflows/ansi-x963-kdf/badge.svg?branch=master&event=push
[build-link]: https://github.com/RustCrypto/KDFs/actions?query=workflow:ansi-x963-kdf
