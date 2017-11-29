# rust-hkdf

[![Build Status](https://travis-ci.org/vladikoff/rust-hkdf.svg?branch=master)](https://travis-ci.org/vladikoff/rust-hkdf)
[![creates.io](https://img.shields.io/crates/v/hkdf.svg)](https://crates.io/crates/hkdf)

[HMAC-based Extract-and-Expand Key Derivation Function (HKDF)](https://tools.ietf.org/html/rfc5869) for [Rust](http://www.rust-lang.org/).
Supports:

- SHA-256
- SHA-1

## Installation

From crates.io:

```toml
[dependencies]
hkdf = "*"
```

From the git repository:

```toml
[dependencies.hkdf]

git = "https://github.com/vladikoff/rust-hkdf.git"
```

## Usage

See the example [examples/main.rs](examples/main.rs) or run it with `cargo run --example main`

## Changelog

- 0.3.0 - update dependencies: digest-0.7, hmac-0.5
- 0.2.0 - support for rustc 1.20.0
- 0.1.1 - fixes to support rustc 1.5.0
- 0.1.0 - initial release

## Authors

[![Vlad Filippov](https://avatars3.githubusercontent.com/u/128755?s=70)](http://vf.io/) | [![Brian Warner](https://avatars3.githubusercontent.com/u/27146?v=4&s=70)](http://www.lothar.com/blog/) 
---|---
[Vlad Filippov](http://vf.io/) | [Brian Warner](http://www.lothar.com/blog/)
