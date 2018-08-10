#![no_std]

extern crate generic_array;
extern crate digest;
extern crate hmac;
#[cfg(feature = "std")] extern crate std;

use core::cmp;
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
    where D: Digest,
          D::OutputSize: ArrayLength<u8>
{
    /// The RFC5869 HKDF-Extract operation
    pub fn extract(salt: Option<&[u8]>, ikm: &[u8]) -> Hkdf<D> {
        let mut hmac = match salt {
            Some(s) => Hmac::<D>::new(s),
            None => Hmac::<D>::new(&generic_array::GenericArray::<u8, D::OutputSize>::default()),
        }.expect("HMAC can accept keys of any size");

        hmac.input(ikm);
        let mut arr = GenericArray::default();
        arr.copy_from_slice(&hmac.result().code());
        Hkdf {
            prk: arr,
        }
    }

    /// The RFC5869 HKDF-Expand operation
    pub fn expand(&self, info: &[u8], okm: &mut [u8]) -> Result<(), InvalidLength> {
        use generic_array::typenum::Unsigned;

        let length = okm.len();
        let mut prev: Option<generic_array::GenericArray<u8, <D as digest::FixedOutput>::OutputSize>> = None;

        let hmac_output_bytes = D::OutputSize::to_usize();
        if length > hmac_output_bytes * 255 {
            return Err(InvalidLength);
        }

        let mut remaining = length;
        let mut blocknum: u32 = 1;
        let mut offset = 0;
        while remaining > 0 {
            let mut output_block = Hmac::<D>::new(&self.prk).unwrap();

            if let Some(ref prev) = prev { output_block.input(prev) };
            output_block.input(info);
            output_block.input(&[blocknum as u8]);

            let output = output_block.result().code();
            let needed = cmp::min(remaining, hmac_output_bytes);

            okm[offset..offset+needed].copy_from_slice(&output[..needed]);
            offset += needed;

            prev = Some(output);
            blocknum += 1;
            remaining -= needed;
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
