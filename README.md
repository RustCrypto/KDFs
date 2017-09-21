# rust-hkdf

[![Build Status](https://travis-ci.org/vladikoff/rust-hkdf.svg?branch=master)](https://travis-ci.org/vladikoff/rust-hkdf)

[HMAC-based Extract-and-Expand Key Derivation Function (HKDF)](https://tools.ietf.org/html/rfc5869) for [Rust](http://www.rust-lang.org/).
Supports:

* SHA-256

## Installation

From crates.io:

```toml
[dependencies]
hkdf = "0.1.1"
```

From the git repository:

```toml
[dependencies.hkdf]

git = "https://github.com/vladikoff/rust-hkdf.git"
```

## Usage

See the example [examples/main.rs](examples/main.rs) or run it with `cargo run --example main`
