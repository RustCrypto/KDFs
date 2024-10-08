//! An implementation of ANSI-X9.63 KDF Key Derivation Function.
//!
//! This function is described in the section 3.6.1 of [SEC 1: Elliptic Curve Cryptography][1].
//!
//! # Usage
//!
//! The most common way to use ANSI-X9.63 KDF is as follows: you generate a shared secret
//! with other party (e.g. via Diffie-Hellman algorithm) and use key derivation function
//! to derive a shared key.
//!
//! ```rust
//! let mut key = [0u8; 32];
//! ansi_x963_kdf::derive_key_into::<sha2::Sha256>(b"shared-secret", b"other-info", &mut key).unwrap();
//! ```
//!
//! [1]: https://www.secg.org/sec1-v2.pdf

#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]

use core::fmt;
use digest::{array::typenum::Unsigned, Digest, FixedOutputReset};

#[cfg(feature = "std")]
extern crate std;

/// ANSI-X9.63 KDF errors.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Error {
    /// The length of the secret is zero.
    NoSecret,
    /// The length of the output is zero.
    NoOutput,
    /// The length of the input is too big
    InputOverflow,
    /// The length of the output is too big.
    CounterOverflow,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        f.write_str(match self {
            Error::NoSecret => "Buffer for secret has zero length.",
            Error::NoOutput => "Buffer for key has zero length.",
            Error::InputOverflow => "Input length is to big.",
            Error::CounterOverflow => "Requested key length is to big.",
        })
    }
}

#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
impl ::std::error::Error for Error {}

/// Derives `key` in-place from `secret` and `shared_info`.
/// ```rust
/// let mut key = [0u8; 42];
/// ansi_x963_kdf::derive_key_into::<sha2::Sha256>(b"top-secret", b"info", &mut key).unwrap();
/// ```
pub fn derive_key_into<D>(secret: &[u8], shared_info: &[u8], key: &mut [u8]) -> Result<(), Error>
where
    D: Digest + FixedOutputReset,
{
    if secret.is_empty() {
        return Err(Error::NoSecret);
    }

    if key.is_empty() {
        return Err(Error::NoOutput);
    }

    // 1. Check if |Z| + |SharedInfo| + 4 >= hashmaxlen
    if secret.len() + shared_info.len() + 4 >= D::OutputSize::USIZE * (u32::MAX as usize) {
        return Err(Error::InputOverflow);
    }

    // Counter overflow is possible only on architectures with usize bigger than 4 bytes.
    const OVERFLOW_IS_POSSIBLE: bool = core::mem::size_of::<usize>() > 4;

    // 2. Check that keydatalen < hashlen × (2^32 − 1)
    if OVERFLOW_IS_POSSIBLE && (key.len() >= D::OutputSize::USIZE * (u32::MAX as usize)) {
        return Err(Error::CounterOverflow);
    }

    let mut digest = D::new();

    // 3. Initiate a 4 octet, big-endian octet string Counter as 00000001
    let mut counter: u32 = 1;

    // 4. For i = 1 to keydatalen/hashlen,
    for chunk in key.chunks_mut(D::OutputSize::USIZE) {
        // 4.1 Compute Ki = Hash(Z ‖ Counter ‖ [SharedInfo]) using the selected hash function
        Digest::update(&mut digest, secret);
        Digest::update(&mut digest, &counter.to_be_bytes());
        Digest::update(&mut digest, shared_info);
        chunk.copy_from_slice(&digest.finalize_reset()[..chunk.len()]);
        // 4.2. Increment Counter
        counter += 1;
    }

    Ok(())
}

/// Derives and returns `length` bytes key from `secret` and `shared_info`.
/// ```rust
/// let key = ansi_x963_kdf::derive_key::<sha2::Sha256>(b"top-secret", b"info", 42).unwrap();
/// ```
#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
pub fn derive_key<D>(
    secret: &[u8],
    shared_info: &[u8],
    length: usize,
) -> Result<std::vec::Vec<u8>, Error>
where
    D: Digest + FixedOutputReset,
{
    let mut key = std::vec![0u8; length];
    derive_key_into::<D>(secret, shared_info, &mut key)?;
    Ok(key)
}
