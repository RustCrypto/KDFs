#![no_std]
#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg"
)]
#![cfg_attr(docsrs, feature(doc_cfg))]

use core::fmt;
use digest::{Digest, FixedOutputReset, Update, array::typenum::Unsigned};

/// Derives `key` in-place using a hash function.
///
/// This is the hash-based One-Step KDF variant. For a configurable
/// auxiliary function, use [`derive_key_into_with`].
///
/// # Example
///
/// ```rust
/// use hex_literal::hex;
/// use sha2::Sha256;
///
/// let mut key = [0u8; 16];
///
/// one_step_kdf::derive_key_into::<Sha256>(
///     b"secret",
///     b"shared-info",
///     &mut key,
/// )
/// .unwrap();
///
/// assert_eq!(
///     key,
///     hex!("960db2c549ab16d71a7b008e005c2bdc")
/// );
/// ```
///
/// # Errors
///
/// - Returns [`Error::NoSecret`] if `secret` is empty.
/// - Returns [`Error::NoOutput`] if `key` is empty.
/// - Returns [`Error::CounterOverflow`] if `key` is too large.
pub fn derive_key_into<D>(secret: &[u8], other_info: &[u8], key: &mut [u8]) -> Result<(), Error>
where
    D: Digest + FixedOutputReset,
{
    derive_key_into_with(D::new(), secret, other_info, key)
}

/// Derives `key` in-place using an initialized auxiliary function.
///
/// The auxiliary function processes each block as:
///
/// ```text
/// counter || secret || other_info
/// ```
///
/// `aux` must be freshly initialized. After finalizing a block, its
/// [`FixedOutputReset`] implementation must restore the same initial
/// configuration.
///
/// This allows the same One-Step KDF implementation to be used with:
///
/// - a digest such as SHA-256;
/// - a keyed construction such as `HmacReset<Sha256>`;
/// - another compatible fixed-output auxiliary function.
///
/// # Errors
///
/// - Returns [`Error::NoSecret`] if `secret` is empty.
/// - Returns [`Error::NoOutput`] if `key` is empty.
/// - Returns [`Error::CounterOverflow`] if `key` is too large.
pub fn derive_key_into_with<A>(
    mut aux: A,
    secret: &[u8],
    other_info: &[u8],
    key: &mut [u8],
) -> Result<(), Error>
where
    A: Update + FixedOutputReset,
{
    if secret.is_empty() {
        return Err(Error::NoSecret);
    }

    if key.is_empty() {
        return Err(Error::NoOutput);
    }

    let output_size = A::OutputSize::USIZE;
    let block_count = block_count(key.len(), output_size)?;

    for (counter, chunk) in (1..=block_count).zip(key.chunks_mut(output_size)) {
        Update::update(&mut aux, &counter.to_be_bytes());
        Update::update(&mut aux, secret);
        Update::update(&mut aux, other_info);

        let block = aux.finalize_fixed_reset();

        chunk.copy_from_slice(&block[..chunk.len()]);
    }

    Ok(())
}

fn block_count(key_len: usize, output_size: usize) -> Result<u32, Error> {
    if output_size == 0 {
        return Err(Error::CounterOverflow);
    }

    u32::try_from(key_len.div_ceil(output_size)).map_err(|_| Error::CounterOverflow)
}

/// One-Step KDF errors.
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
            Error::CounterOverflow => "Requested key length is too big.",
        })
    }
}

impl core::error::Error for Error {}

#[cfg(test)]
mod tests {
    use super::{Error, block_count};

    #[test]
    fn maximum_block_count_is_accepted() {
        let maximum = usize::try_from(u32::MAX).expect("usize is at least 32 bits");

        assert_eq!(block_count(maximum, 1), Ok(u32::MAX));

        #[cfg(target_pointer_width = "64")]
        assert_eq!(block_count(maximum + 1, 1), Err(Error::CounterOverflow));
    }
}
