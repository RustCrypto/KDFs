#![no_std]
#![doc = include_str!("../README.md")]

use core::{fmt, marker::PhantomData, ops::Mul};
use digest::{
    array::{typenum::Unsigned, Array, ArraySize},
    consts::{U32, U8},
    crypto_common::KeySizeUser,
    typenum::op,
    KeyInit, Mac,
};

pub mod sealed;

#[derive(Debug, PartialEq)]
pub enum Error {
    InvalidRequestSize,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::InvalidRequestSize => write!(
                f,
                "Request output size is too large for the value of R specified"
            ),
        }
    }
}

impl core::error::Error for Error {}

/// Parameters used for KBKDF
pub struct Params<'k, 'l, 'c> {
    pub kin: &'k [u8],
    pub label: &'l [u8],
    pub context: &'c [u8],
    pub use_l: bool,
    pub use_separator: bool,
    pub use_counter: bool,
}

impl<'k, 'l, 'c> Params<'k, 'l, 'c> {
    /// Create a new builder for [`Params`]
    pub fn builder(kin: &'k [u8]) -> ParamsBuilder<'k, 'l, 'c> {
        let params = Params {
            kin,
            label: &[],
            context: &[],
            use_l: true,
            use_separator: true,
            use_counter: true,
        };
        ParamsBuilder(params)
    }
}

/// Parameters builders for [`Params`]
pub struct ParamsBuilder<'k, 'l, 'c>(Params<'k, 'l, 'c>);

impl<'k, 'l, 'c> ParamsBuilder<'k, 'l, 'c> {
    /// Return the built [`Params`]
    pub fn build(self) -> Params<'k, 'l, 'c> {
        self.0
    }

    /// Set the label for the parameters
    pub fn with_label(mut self, label: &'l [u8]) -> Self {
        self.0.label = label;
        self
    }

    /// Set the context for the parameters
    pub fn with_context(mut self, context: &'c [u8]) -> Self {
        self.0.context = context;
        self
    }

    /// During the iterations, append the length of the Prf
    pub fn use_l(mut self, use_l: bool) -> Self {
        self.0.use_l = use_l;
        self
    }

    /// During the iterations, separate the label from the context with a NULL byte
    pub fn use_separator(mut self, use_separator: bool) -> Self {
        self.0.use_separator = use_separator;
        self
    }

    /// During the iterations, update the Prf with the iteration counter
    pub fn use_counter(mut self, use_counter: bool) -> Self {
        self.0.use_counter = use_counter;
        self
    }
}

// Helper structure along with [`KbkdfUser`] to compute values of L and H.
struct KbkdfCore<OutputLen, PrfOutputLen> {
    _marker: PhantomData<(OutputLen, PrfOutputLen)>,
}

trait KbkdfUser {
    // L - An integer specifying the requested length (in bits) of the derived keying material
    // KOUT. L is represented as a bit string when it is an input to a key-derivation function. The
    // length of the bit string is specified by the encoding method for the input data.
    type L;

    // h - An integer that indicates the length (in bits) of the output of a single invocation of the
    // PRF.
    type H;
}

impl<OutputLen, PrfOutputLen> KbkdfUser for KbkdfCore<OutputLen, PrfOutputLen>
where
    OutputLen: ArraySize + Mul<U8>,
    <OutputLen as Mul<U8>>::Output: Unsigned,
    PrfOutputLen: ArraySize + Mul<U8>,
    <PrfOutputLen as Mul<U8>>::Output: Unsigned,
{
    type L = op!(OutputLen * U8);
    type H = op!(PrfOutputLen * U8);
}

/// [`Kbkdf`] is a trait representing a mode of KBKDF.
/// It takes multiple arguments:
///  - Prf - the Pseudorandom Function to derive keys from
///  - K - the expected output length of the newly derived key
///  - R - An integer (1 <= r <= 32) that indicates the length of the binary encoding of the counter i
///        as an integer in the interval [1, 2r − 1].
pub trait Kbkdf<Prf, K, R: sealed::R>
where
    Prf: Mac + KeyInit,
    K: KeySizeUser,
    K::KeySize: ArraySize + Mul<U8>,
    <K::KeySize as Mul<U8>>::Output: Unsigned,
    Prf::OutputSize: ArraySize + Mul<U8>,
    <Prf::OutputSize as Mul<U8>>::Output: Unsigned,
{
    /// Derives `key` from `kin` and other parameters.
    fn derive(&self, params: Params) -> Result<Array<u8, K::KeySize>, Error> {
        // n - An integer whose value is the number of iterations of the PRF needed to generate L
        // bits of keying material
        let n: u32 = <KbkdfCore<K::KeySize, Prf::OutputSize> as KbkdfUser>::L::U32
            .div_ceil(<KbkdfCore<K::KeySize, Prf::OutputSize> as KbkdfUser>::H::U32);

        if n as usize > 2usize.pow(R::U32) - 1 {
            return Err(Error::InvalidRequestSize);
        }

        let mut output = Array::<u8, K::KeySize>::default();
        let mut builder = output.as_mut_slice();

        let mut ki = None;
        self.input_iv(&mut ki);
        let mut a = {
            let mut h = Prf::new_from_slice(params.kin).unwrap();
            h.update(params.label);
            if params.use_separator {
                h.update(&[0]);
            }
            h.update(params.context);
            h.finalize().into_bytes()
        };

        for counter in 1..=n {
            if counter > 1 {
                a = {
                    let mut h = Prf::new_from_slice(params.kin).unwrap();
                    h.update(a.as_slice());
                    h.finalize().into_bytes()
                };
            }

            let mut h = Prf::new_from_slice(params.kin).unwrap();

            if Self::FEEDBACK_KI {
                if let Some(ki) = ki {
                    h.update(ki.as_slice());
                }
            }

            if Self::DOUBLE_PIPELINE {
                h.update(a.as_slice());
            }
            if params.use_counter {
                // counter encoded as big endian u32
                // Type parameter R encodes how large the value is to be (either U8, U16, U24, or U32)
                //
                // counter = 1u32 ([0, 0, 0, 1])
                //                     \-------/
                //                      R = u24
                h.update(&counter.to_be_bytes()[(4 - R::USIZE / 8)..]);
            }

            // Fixed input data
            h.update(params.label);
            if params.use_separator {
                h.update(&[0]);
            }
            h.update(params.context);
            if params.use_l {
                h.update(
                    &(<KbkdfCore<K::KeySize, Prf::OutputSize> as KbkdfUser>::L::U32).to_be_bytes()
                        [..],
                );
            }

            let buf = h.finalize().into_bytes();
            ki = Some(buf.clone());

            let remaining = usize::min(buf.len(), builder.len());

            builder[..remaining].copy_from_slice(&buf[..remaining]);
            builder = &mut builder[remaining..];
        }

        assert_eq!(builder.len(), 0, "output has uninitialized bytes");

        Ok(output)
    }

    /// Input the IV in the PRF
    fn input_iv(&self, _ki: &mut Option<Array<u8, Prf::OutputSize>>) {}

    /// Whether the KI should be reinjected every round.
    const FEEDBACK_KI: bool = false;

    const DOUBLE_PIPELINE: bool = false;
}

pub struct Counter<Prf, K, R = U32> {
    _marker: PhantomData<(Prf, K, R)>,
}

impl<Prf, K, R> Default for Counter<Prf, K, R> {
    fn default() -> Self {
        Self {
            _marker: PhantomData,
        }
    }
}

impl<Prf, K, R> Kbkdf<Prf, K, R> for Counter<Prf, K, R>
where
    Prf: Mac + KeyInit,
    K: KeySizeUser,
    K::KeySize: ArraySize + Mul<U8>,
    <K::KeySize as Mul<U8>>::Output: Unsigned,
    Prf::OutputSize: ArraySize + Mul<U8>,
    <Prf::OutputSize as Mul<U8>>::Output: Unsigned,
    R: sealed::R,
{
}

pub struct Feedback<'a, Prf, K, R = U32>
where
    Prf: Mac,
{
    iv: Option<&'a Array<u8, Prf::OutputSize>>,
    _marker: PhantomData<(Prf, K, R)>,
}

impl<'a, Prf, K, R> Feedback<'a, Prf, K, R>
where
    Prf: Mac,
{
    pub fn new(iv: Option<&'a Array<u8, Prf::OutputSize>>) -> Self {
        Self {
            iv,
            _marker: PhantomData,
        }
    }
}

impl<'a, Prf, K, R> Kbkdf<Prf, K, R> for Feedback<'a, Prf, K, R>
where
    Prf: Mac + KeyInit,
    K: KeySizeUser,
    K::KeySize: ArraySize + Mul<U8>,
    <K::KeySize as Mul<U8>>::Output: Unsigned,
    Prf::OutputSize: ArraySize + Mul<U8>,
    <Prf::OutputSize as Mul<U8>>::Output: Unsigned,
    R: sealed::R,
{
    fn input_iv(&self, ki: &mut Option<Array<u8, Prf::OutputSize>>) {
        if let Some(iv) = self.iv {
            *ki = Some(iv.clone())
        }
    }

    const FEEDBACK_KI: bool = true;
}

pub struct DoublePipeline<Prf, K, R = U32>
where
    Prf: Mac,
{
    _marker: PhantomData<(Prf, K, R)>,
}

impl<Prf, K, R> Default for DoublePipeline<Prf, K, R>
where
    Prf: Mac,
{
    fn default() -> Self {
        Self {
            _marker: PhantomData,
        }
    }
}

impl<Prf, K, R> Kbkdf<Prf, K, R> for DoublePipeline<Prf, K, R>
where
    Prf: Mac + KeyInit,
    K: KeySizeUser,
    K::KeySize: ArraySize + Mul<U8>,
    <K::KeySize as Mul<U8>>::Output: Unsigned,
    Prf::OutputSize: ArraySize + Mul<U8>,
    <Prf::OutputSize as Mul<U8>>::Output: Unsigned,
    R: sealed::R,
{
    const DOUBLE_PIPELINE: bool = true;
}

#[cfg(test)]
mod tests;
