//! An implementation of HKDF, the [HMAC-based Extract-and-Expand Key Derivation Function][1].
//!
//! # Usage
//!
//! ```rust
//! # extern crate hex;
//! # extern crate hkdf;
//! # extern crate sha2;
//!
//! # use sha2::Sha256;
//! # use hkdf::Hkdf;
//!
//! # fn main() {
//! let ikm = hex::decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
//! let salt = hex::decode("000102030405060708090a0b0c").unwrap();
//! let info = hex::decode("f0f1f2f3f4f5f6f7f8f9").unwrap();
//!
//! let hk = Hkdf::<Sha256>::extract(Some(&salt[..]), &ikm);
//! let mut okm = [0u8; 42];
//! hk.expand(&info, &mut okm).unwrap();
//! println!("PRK is {}", hex::encode(hk.prk));
//! println!("OKM is {}", hex::encode(&okm[..]));
//! # }
//! ```
//!
//! [1]: https://tools.ietf.org/html/rfc5869
#![no_std]

extern crate digest;
extern crate hmac;
#[cfg(feature = "std")] extern crate std;

use digest::{BlockInput, FixedOutput, Input, Reset};
use digest::generic_array::{self, ArrayLength, GenericArray};
use hmac::{Hmac, Mac};
use core::fmt;

/// Structure for InvalidLength, used for output error handling.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct InvalidLength;

/// Structure representing the HKDF, capable of HKDF-Expand and HKDF-extract operations.
#[derive(Clone)]
pub struct Hkdf<D>
    where D: Input + BlockInput + FixedOutput + Reset + Default + Clone,
          D::OutputSize: ArrayLength<u8>,
{
    pub prk: GenericArray<u8, D::OutputSize>,
}

impl<D> Hkdf<D>
    where D: Input + BlockInput + FixedOutput + Reset + Default + Clone,
          D::BlockSize: ArrayLength<u8> + Clone,
          D::OutputSize: ArrayLength<u8>,
{
    /// The RFC5869 HKDF-Extract operation
    pub fn extract(salt: Option<&[u8]>, ikm: &[u8]) -> Hkdf<D> {
        let mut hmac = match salt {
            Some(s) => Hmac::<D>::new_varkey(s).expect("HMAC can take a key of any size"),
            None => Hmac::<D>::new(&Default::default()),
        };

        hmac.input(ikm);
        Hkdf {
            prk: hmac.result().code(),
        }
    }

    /// The RFC5869 HKDF-Expand operation
    pub fn expand(&self, info: &[u8], okm: &mut [u8]) -> Result<(), InvalidLength> {
        use generic_array::typenum::Unsigned;

        let mut prev: Option<GenericArray<u8, <D as digest::FixedOutput>::OutputSize>> = None;

        let hmac_output_bytes = D::OutputSize::to_usize();
        if okm.len() > hmac_output_bytes * 255 {
            return Err(InvalidLength);
        }

        let mut hmac = Hmac::<D>::new_varkey(&self.prk).unwrap();
        for (blocknum, okm_block) in okm.chunks_mut(hmac_output_bytes).enumerate() {
            let block_len = okm_block.len();

            if let Some(ref prev) = prev { hmac.input(prev) };
            hmac.input(info);
            hmac.input(&[blocknum as u8 + 1]);

            let output = hmac.result_reset().code();
            okm_block.copy_from_slice(&output[..block_len]);

            prev = Some(output);
        }

        Ok(())
    }
}

impl fmt::Display for InvalidLength {
    fn fmt(&self, f: & mut fmt::Formatter) -> Result<(), fmt::Error> {
        f.write_str("invalid number of blocks, too large output")
    }
}

#[cfg(feature = "std")]
impl ::std::error::Error for InvalidLength {}
