# RustCrypto: bake-kdf

[![crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
![Apache2/MIT licensed][license-image]
![Rust Version][rustc-image]
[![Project Chat][chat-image]][chat-link]
[![Build Status][build-image]][build-link]

Pure Rust implementation of the [bake-kdf](https://apmi.bsu.by/assets/files/std/bake-spec19.pdf) function.

# Usage
```rust
use bake_kdf::bake_kdf;
let x = vec![0x00; 32];
let s = vec![0x00; 8];
let c = 0x00;
let key = bake_kdf(&x, &s, c).unwrap();
```


[//]: # (badges)

[crate-image]: https://img.shields.io/crates/v/bake-kdf.svg
[crate-link]: https://crates.io/crates/bake-kdf
[docs-image]: https://docs.rs/bake-kdf/badge.svg
[docs-link]: https://docs.rs/bake-kdf/
[license-image]: https://img.shields.io/badge/license-Apache2.0/MIT-blue.svg
[rustc-image]: https://img.shields.io/badge/rustc-1.41+-blue.svg
[chat-image]: https://img.shields.io/badge/zulip-join_chat-blue.svg
[chat-link]: https://rustcrypto.zulipchat.com/#narrow/stream/260043-KDFs
[build-image]: https://github.com/RustCrypto/KDFs/workflows/bake-kdf/badge.svg?branch=master&event=push
[build-link]: https://github.com/RustCrypto/KDFs/actions?query=workflow:bake-kdf
