#![no_std]
#![doc = include_str!("../README.md")]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]

use core::fmt;
use digest::{array::typenum::Unsigned, Digest, FixedOutputReset, Update};

#[cfg(feature = "alloc")]
extern crate alloc;

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

impl ::core::error::Error for Error {}

/// Derives `key` in-place from `secret` and `other_info`.
///
/// # Example
/// ```rust
/// use hex_literal::hex;
/// use sha2::Sha256;
///
/// let mut key = [0u8; 16];
/// concat_kdf::derive_key_into::<Sha256>(b"secret", b"shared-info", &mut key).unwrap();
/// assert_eq!(key, hex!("960db2c549ab16d71a7b008e005c2bdc"));
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

    // Key length shall be less than or equal to hash output length * (2^32 - 1).
    if (key.len() as u64) >= D::OutputSize::U64 * (u32::MAX as u64) {
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
///
/// # Example
/// ```rust
/// use hex_literal::hex;
/// use sha2::Sha256;
///
/// let key = concat_kdf::derive_key::<Sha256>(b"secret", b"shared-info", 16).unwrap();
/// assert_eq!(key[..], hex!("960db2c549ab16d71a7b008e005c2bdc")[..]);
/// ```
#[cfg(feature = "alloc")]
pub fn derive_key<D>(
    secret: &[u8],
    other_info: &[u8],
    length: usize,
) -> Result<alloc::boxed::Box<[u8]>, Error>
where
    D: Digest + FixedOutputReset,
{
    let mut key = alloc::vec![0u8; length].into_boxed_slice();
    derive_key_into::<D>(secret, other_info, &mut key)?;
    Ok(key)
}
