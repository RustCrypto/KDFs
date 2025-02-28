# RustCrypto: bake-kdf

[![crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
[![Build Status][build-image]][build-link]
![Apache2/MIT licensed][license-image]
![Rust Version][rustc-image]
[![Project Chat][chat-image]][chat-link]


Pure Rust implementation of the [bake-kdf][1] function.

[1]: https://apmi.bsu.by/assets/files/std/bake-spec19.pdf

# Examples

```rust
use bake_kdf::bake_kdf;
use hex_literal::hex;
let x = [0x42; 32];
let s = [0x24; 8];
let c = 0x00;
let key = bake_kdf(&x, &s, c);

assert_eq!(key, hex!("bbd7ece0080bee33c776a140f8d807a113a119a4e4d4270f9f2018fbd5e6292e"));
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

[crate-image]: https://img.shields.io/crates/v/bake-kdf.svg?logo=rust
[crate-link]: https://crates.io/crates/bake-kdf
[docs-image]: https://docs.rs/bake-kdf/badge.svg
[docs-link]: https://docs.rs/bake-kdf/
[build-image]: https://github.com/RustCrypto/KDFs/actions/workflows/bake-kdf.yml/badge.svg
[build-link]: https://github.com/RustCrypto/KDFs/actions/workflows/bake-kdf.yml
[license-image]: https://img.shields.io/badge/license-Apache2.0/MIT-blue.svg
[rustc-image]: https://img.shields.io/badge/rustc-1.85+-blue.svg
[chat-image]: https://img.shields.io/badge/zulip-join_chat-blue.svg
[chat-link]: https://rustcrypto.zulipchat.com/#narrow/stream/260043-KDFs
