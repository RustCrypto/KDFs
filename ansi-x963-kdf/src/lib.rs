#![no_std]
#![doc = include_str!("../README.md")]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]

use core::fmt;
use digest::{array::typenum::Unsigned, Digest, FixedOutputReset};

#[cfg(feature = "alloc")]
extern crate alloc;

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

impl ::core::error::Error for Error {}

/// Derives `key` in-place from `secret` and `shared_info`.
///
/// # Example
/// ```
/// use hex_literal::hex;
/// use sha2::Sha256;
///
/// let mut key = [0u8; 16];
/// ansi_x963_kdf::derive_key_into::<Sha256>(b"secret", b"shared-info", &mut key).unwrap();
/// assert_eq!(key, hex!("8dbb1d50bcc7fc782abc9db5c64a2826"));
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

    // 1. Check that |Z| + |SharedInfo| + 4 < hashmaxlen
    // where "hashmaxlen denote the maximum length in octets of messages that can be hashed using Hash".
    // N.B.: `D::OutputSize::U64 * (u32::MAX as u64)`` is currently used as an approximation of hashmaxlen.
    if secret.len() as u64 + shared_info.len() as u64 + 4 >= D::OutputSize::U64 * (u32::MAX as u64)
    {
        return Err(Error::InputOverflow);
    }

    // 2. Check that keydatalen < hashlen × (2^32 − 1)
    if key.len() as u64 >= D::OutputSize::U64 * (u32::MAX as u64) {
        return Err(Error::CounterOverflow);
    }

    let mut digest = D::new();

    // 3. Initiate a 4 octet, big-endian octet string Counter as 00000001
    let mut counter: u32 = 1;

    // 4. For i = 1 to keydatalen/hashlen,
    for chunk in key.chunks_mut(D::OutputSize::USIZE) {
        // 4.1 Compute Ki = Hash(Z ‖ Counter ‖ [SharedInfo]) using the selected hash function
        Digest::update(&mut digest, secret);
        Digest::update(&mut digest, counter.to_be_bytes());
        Digest::update(&mut digest, shared_info);
        chunk.copy_from_slice(&digest.finalize_reset()[..chunk.len()]);
        // 4.2. Increment Counter
        counter += 1;
    }

    Ok(())
}

/// Derives and returns `length` bytes key from `secret` and `shared_info`.
///
/// # Example
/// ```
/// use hex_literal::hex;
/// use sha2::Sha256;
///
/// let key = ansi_x963_kdf::derive_key::<Sha256>(b"secret", b"shared-info", 42).unwrap();
/// assert_eq!(key, hex!("8dbb1d50bcc7fc782abc9db5c64a2826"));
/// ```
#[cfg(feature = "alloc")]
pub fn derive_key<D>(
    secret: &[u8],
    shared_info: &[u8],
    length: usize,
) -> Result<alloc::boxed::Box<[u8]>, Error>
where
    D: Digest + FixedOutputReset,
{
    let mut key = alloc::vec![0u8; length].into_boxed_slice();
    derive_key_into::<D>(secret, shared_info, &mut key)?;
    Ok(key)
}
