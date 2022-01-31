#![no_std]

use core::fmt;
use digest::{generic_array::typenum::Unsigned, Digest, FixedOutputReset, Update};

#[cfg(feature = "std")]
extern crate std;

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Error {
    NoSecret,
    ZeroOutput,
    CounterOverflow,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        let msg = match self {
            Error::NoSecret => "No secret was provided.",
            Error::ZeroOutput => "Buffer for key has zero length.",
            Error::CounterOverflow => "Requested key length is to big.",
        };
        f.write_str(msg)
    }
}

#[cfg(feature = "std")]
impl ::std::error::Error for Error {}

fn chunk_number(length: usize, chunk_size: usize) -> usize {
    let mut number = length / chunk_size;
    if length % chunk_size != 0 {
        number += 1;
    }

    number
}

pub fn derive_key_into<D>(secret: &[u8], other_info: &[u8], key: &mut [u8]) -> Result<(), Error>
where
    D: Digest + FixedOutputReset,
{
    if secret.len() == 0 {
        return Err(Error::NoSecret);
    }

    if key.len() == 0 {
        return Err(Error::ZeroOutput);
    }

    if chunk_number(key.len(), D::OutputSize::USIZE) >= (u32::MAX as usize) {
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

#[cfg(feature = "std")]
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
