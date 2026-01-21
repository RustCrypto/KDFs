# RustCrypto: Key Derivation Functions

[![Project Chat][chat-image]][chat-link]
[![dependency status][deps-image]][deps-link]
![Apache2/MIT licensed][license-image]

Collection of [Key Derivation Functions][KDF] (KDF) written in pure Rust.

## Supported Algorithms

| Algorithm    | Crate | Crates.io | Documentation | MSRV |
|--------------|-------|:---------:|:-------------:|:----:|
| [ANSI-X9.63-KDF] | [`ansi-x963-kdf`] | [![crates.io](https://img.shields.io/crates/v/ansi-x963-kdf.svg)](https://crates.io/crates/ansi-x963-kdf) | [![Documentation](https://docs.rs/ansi-x963-kdf/badge.svg)](https://docs.rs/ansi-x963-kdf) | ![MSRV 1.85][msrv-1.85] |
| [bake-kdf]   | [`bake-kdf`]   |   [![crates.io](https://img.shields.io/crates/v/bake-kdf.svg)](https://crates.io/crates/bake-kdf)   |   [![Documentation](https://docs.rs/bake-kdf/badge.svg)](https://docs.rs/bake-kdf)   | ![MSRV 1.85][msrv-1.85] |
| [Concat-KDF] | [`concat-kdf`] | [![crates.io](https://img.shields.io/crates/v/concat-kdf.svg)](https://crates.io/crates/concat-kdf) | [![Documentation](https://docs.rs/concat-kdf/badge.svg)](https://docs.rs/concat-kdf) | ![MSRV 1.85][msrv-1.85] |
| [HKDF]       | [`hkdf`]       |       [![crates.io](https://img.shields.io/crates/v/hkdf.svg)](https://crates.io/crates/hkdf)       |       [![Documentation](https://docs.rs/hkdf/badge.svg)](https://docs.rs/hkdf)       | ![MSRV 1.85][msrv-1.85] |
| [KBKDF]      | [`kbkdf`]      | [![crates.io](https://img.shields.io/crates/v/kbkdf.svg)](https://crates.io/crates/kbkdf)       |       [![Documentation](https://docs.rs/kbkdf/badge.svg)](https://docs.rs/kbkdf)         | ![MSRV 1.85][msrv-1.85] |

*NOTE: for password-based KDFs (e.g. Argon2, PBKDF2, scrypt), please see [RustCrypto/password-hashes]*

## License

All crates licensed under either of

 * [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)
 * [MIT license](http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.

[//]: # (badges)

[chat-image]: https://img.shields.io/badge/zulip-join_chat-blue.svg
[chat-link]: https://rustcrypto.zulipchat.com/#narrow/stream/260043-KDFs
[license-image]: https://img.shields.io/badge/license-Apache2.0/MIT-blue.svg
[deps-image]: https://deps.rs/repo/github/RustCrypto/KDFs/status.svg
[deps-link]: https://deps.rs/repo/github/RustCrypto/KDFs
[msrv-1.85]: https://img.shields.io/badge/rustc-1.85+-blue.svg

[//]: # (crates)

[`ansi-x963-kdf`]: ./ansi-x963-kdf
[`bake-kdf`]: ./bake-kdf
[`concat-kdf`]: ./concat-kdf
[`hkdf`]: ./hkdf
[`kbkdf`]: ./kbkdf

[//]: # (algorithms)

[KDF]: https://en.wikipedia.org/wiki/Key_derivation_function
[HKDF]: https://en.wikipedia.org/wiki/HKDF
[ANSI-X9.63-KDF]: https://www.secg.org/sec1-v2.pdf
[bake-kdf]: https://apmi.bsu.by/assets/files/std/bake-spec19.pdf
[Concat-KDF]: https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-56ar.pdf
[KBKDF]: https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/key-derivation
[RustCrypto/password-hashes]: https://github.com/RustCrypto/password-hashes
