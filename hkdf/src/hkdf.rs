#![no_std]

extern crate generic_array;
extern crate digest;
extern crate hmac;
#[cfg(feature = "std")] extern crate std;

use digest::Digest;
use generic_array::{ArrayLength, GenericArray};
use hmac::{Hmac, Mac};
use core::fmt;

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct InvalidLength;

#[derive(Clone)]
pub struct Hkdf<D>
    where D: Digest,
          D::OutputSize: ArrayLength<u8>
{
    pub prk: GenericArray<u8, D::OutputSize>,
}

impl<D> Hkdf<D>
    where D: Digest + Clone,
          D::OutputSize: ArrayLength<u8>
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

        let mut prev: Option<generic_array::GenericArray<u8, <D as digest::FixedOutput>::OutputSize>> = None;

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

            let output = hmac.result().code();
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
