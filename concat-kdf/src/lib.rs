//! An implementation of Concat KDF, the Concatenation Key Derivation Function.
//!
//! This function is described in the section 5.8.1 of [NIST SP 800-56A, Recommendation
//! for Pair-Wise Key Establishment Schemes Using Discrete Logarithm Cryptography][1].
//!
//! # Usage
//!
//! The most common way to use Concat KDF is as follows: you generate a shared secret
//! with other party (e.g. via Diffie-Hellman algorithm) and use key derivation function
//! to derive a shared key.
//!
//! ```rust
//! let mut key = [0u8; 32];
//! concat_kdf::derive_key_into::<sha2::Sha256>(b"shared-secret", b"other-info", &mut key).unwrap();
//! ```
//!
//! [1]: https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-56ar.pdf

#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]

use core::fmt;
use digest::{generic_array::typenum::Unsigned, Digest, FixedOutputReset, Update};

#[cfg(feature = "std")]
extern crate std;

/// Concat KDF errors.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Error {
    /// The length of the secret is zero.
    NoSecret,
    /// The length of the output is zero.
    NoOutput,
    /// The length of the output is too big.
    CounterOverflow,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        f.write_str(match self {
            Error::NoSecret => "Buffer for secret has zero length.",
            Error::NoOutput => "Buffer for key has zero length.",
            Error::CounterOverflow => "Requested key length is to big.",
        })
    }
}

#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
impl ::std::error::Error for Error {}

/// Derives `key` in-place from `secret` and `other_info`.
/// ```rust
/// let mut key = [0u8; 42];
/// concat_kdf::derive_key_into::<sha2::Sha256>(b"top-secret", b"info", &mut key).unwrap();
/// ```
pub fn derive_key_into<D>(secret: &[u8], other_info: &[u8], key: &mut [u8]) -> Result<(), Error>
where
    D: Digest + FixedOutputReset,
{
    if secret.is_empty() {
        return Err(Error::NoSecret);
    }

    if key.is_empty() {
        return Err(Error::NoOutput);
    }

    // Counter overflow is possible only on architectures with usize bigger than 4 bytes.
    const OVERFLOW_IS_POSSIBLE: bool = core::mem::size_of::<usize>() > 4;

    // Key length shall be less than or equal to hash output length * (2^32 - 1).
    if OVERFLOW_IS_POSSIBLE && (key.len() >= D::OutputSize::USIZE * (u32::MAX as usize)) {
        return Err(Error::CounterOverflow);
    }

    let mut digest = D::new();
    let mut counter: u32 = 1;

    for chunk in key.chunks_mut(D::OutputSize::USIZE) {
        Update::update(&mut digest, &counter.to_be_bytes());
        Update::update(&mut digest, secret);
        Update::update(&mut digest, other_info);
        chunk.copy_from_slice(&digest.finalize_reset()[..chunk.len()]);
        counter += 1;
    }

    Ok(())
}

/// Derives and returns `length` bytes key from `secret` and `other_info`.
/// ```rust
/// let key = concat_kdf::derive_key::<sha2::Sha256>(b"top-secret", b"info", 42).unwrap();
/// ```
#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
pub fn derive_key<D>(
    secret: &[u8],
    other_info: &[u8],
    length: usize,
) -> Result<std::vec::Vec<u8>, Error>
where
    D: Digest + FixedOutputReset,
{
    let mut key = std::vec![0u8; length];
    derive_key_into::<D>(secret, other_info, &mut key)?;
    Ok(key)
}
