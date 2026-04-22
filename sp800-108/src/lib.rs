#![no_std]
#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg"
)]
#![cfg_attr(docsrs, feature(doc_cfg))]

use core::marker::PhantomData;

pub use digest::{FixedOutput, KeyInit, Update};
pub use kdf::Kdf;

/// The maximum number of [`ContextComponent`]s that can be passed to [`NistSp800_108KDF::new()`].
pub const MAX_CONTEXT_COMPONENTS: usize = 16;

/// Specifies a specific input to the PRF when deriving a key.
///
/// The NIST SP 800-108 KDFs generate their output one block at a time
/// where a block is a single output of the underlying PRF.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContextComponent<'a> {
    /// No input. If used, must be after any others.
    ///
    /// Generally, there is no need for developers to use this value.
    Null,
    /// Big-endian block counter with a specified bit-length.
    /// The bit-length must be a positive multiple of 8 and no greater than 64.
    BeCounter(u32),
    /// The `non-secret` input to [`Kdf::derive_key()`].
    NonSecret,
    /// The prior-block or the supplied `iv` value (may be empty).
    Feedback(&'a [u8]),
    /// The block generated when both the counter and `K0` are omitted.
    /// See section 4.1 of the [specification](https://csrc.nist.gov/pubs/sp/800/108/r1/upd1/final)
    /// for more information.
    K0,
    /// The bytes corresponding to the provided string.
    ConstantString(&'a str),
    /// The provided bytes.
    ConstantBytes(&'a [u8]),
    /// The length in bytes of the requested derived key.
    /// It is encoded as a big-endian number with the specified number of bits.
    /// The the specified bit-length must be a positive multiple of 8 and no greater than 64.
    BeLength(usize),
}

/// Structure representing the KDF, generic over a PRF `P`.
/// Depending on configuration, it can represent a counter KDF,
/// a feedback KDF, or a combination of the two.
///
/// The PRF `P` should generally be either an implementation of
/// [`Hmac`](https://docs.rs/hmac/0.13.0/hmac/struct.Hmac.html)
/// or of [`Cmac`](https://docs.rs/cmac/latest/cmac/struct.Cmac.html).
#[derive(Debug)]
pub struct NistSp800_108KDF<'a, P>
where
    P: FixedOutput + KeyInit + Clone,
{
    context: [ContextComponent<'a>; MAX_CONTEXT_COMPONENTS],
    summary: ContextSummary,
    phantom: PhantomData<P>,
}

impl<'a, P> NistSp800_108KDF<'a, P>
where
    P: FixedOutput + KeyInit + Clone,
{
    /// Construct a new KDF instance where the input to the PRF is defined by `context`.
    ///
    /// `context` must be no longer than [`MAX_CONTEXT_COMPONENTS`].
    /// `context` should not contain any instances of [`ContextComponent::Null`],
    /// but if it does, they must be after all non-null values.
    ///
    /// # Errors
    ///
    /// Will return `Err` in any of the following cases:
    ///
    /// - `context` is longer than [`MAX_CONTEXT_COMPONENTS`].
    /// - `context` has any `ContextComponent::Null` values before non-null values.
    /// - `context` does not have any non-null values.
    pub fn new(context: &[ContextComponent<'a>]) -> kdf::Result<Self> {
        if context.len() > MAX_CONTEXT_COMPONENTS {
            return Err(kdf::Error);
        }
        let summary = Self::summarize_context(context);
        if summary.last_non_null_idx.is_none() {
            return Err(kdf::Error);
        }
        if let Some(min_null) = summary.first_null_idx {
            if let Some(max_non_null) = summary.last_non_null_idx
                && min_null < max_non_null
            {
                // There are components after the first null component
                return Err(kdf::Error);
            }
        }
        let mut result = Self {
            context: [ContextComponent::Null; MAX_CONTEXT_COMPONENTS],
            summary,
            phantom: PhantomData,
        };
        result.context[0..context.len()].copy_from_slice(context);
        Ok(result)
    }

    fn summarize_context(context: &[ContextComponent]) -> ContextSummary {
        context
            .iter()
            .enumerate()
            .fold(ContextSummary::default(), |mut acc, v| -> ContextSummary {
                match v.1 {
                    ContextComponent::BeCounter(length) => {
                        acc.min_ctr = acc
                            .min_ctr
                            .map_or(Some(*length), |old_length| Some(old_length.min(*length)));
                    }
                    ContextComponent::NonSecret => acc.has_non_secret = true,
                    ContextComponent::K0 => acc.has_k0 = true,
                    _ => (), // NOP,
                }
                if v.1 == &ContextComponent::Null {
                    if acc.first_null_idx.is_none() {
                        acc.first_null_idx = Some(v.0);
                    }
                } else {
                    acc.last_non_null_idx = Some(v.0);
                }
                acc
            })
    }

    fn calculate_block(
        &self,
        mut prf: P,
        non_secret: &[u8],
        counter: u64,
        feedback: &Option<digest::Output<P>>,
        k0: &Option<digest::Output<P>>,
        output_len: usize,
    ) -> kdf::Result<digest::Output<P>> {
        for c in self.context {
            match c {
                ContextComponent::Null => (),
                ContextComponent::BeCounter(length) => {
                    if counter > 0 {
                        Self::update_be_ctr(&mut prf, counter, length as usize)?;
                    }
                }
                ContextComponent::NonSecret => Update::update(&mut prf, non_secret),
                ContextComponent::Feedback(iv) => Self::update_option(&mut prf, feedback, iv),
                ContextComponent::K0 => Self::update_option(&mut prf, k0, &[]),
                ContextComponent::ConstantString(value) => {
                    Update::update(&mut prf, value.as_bytes());
                }
                ContextComponent::ConstantBytes(value) => Update::update(&mut prf, value),
                ContextComponent::BeLength(length) => {
                    Self::update_be_ctr(&mut prf, output_len as u64, length)?;
                }
            }
        }

        Ok(prf.finalize_fixed())
    }

    fn update_be_ctr(prf: &mut P, counter: u64, length: usize) -> kdf::Result<()> {
        if counter >> length != 0 {
            // Counter overflow
            return Err(kdf::Error);
        }
        let bytes = counter.to_be_bytes();
        Update::update(prf, &bytes[bytes.len() - (length / 8)..bytes.len()]);
        Ok(())
    }

    fn update_option(prf: &mut P, value: &Option<digest::Output<P>>, default: &[u8]) {
        if let Some(data) = value {
            Update::update(prf, data);
        } else {
            Update::update(prf, default);
        }
    }
}

impl<'a, P> Kdf for NistSp800_108KDF<'a, P>
where
    P: FixedOutput + KeyInit + Clone,
{
    /// Writes uniformly random data suitable as key material into the entire length of out
    /// as described by  [`Kdf::derive_key()`].
    ///
    /// # Errors
    ///
    /// Will return `Err` in any of the following cases:
    ///
    /// - `out` is long enough that a counter in the context would overflow
    /// - `non_secret` contains data but there is no corresponding [`ContextComponent::NonSecret`] to emit it.
    fn derive_key(&self, secret: &[u8], non_secret: &[u8], out: &mut [u8]) -> kdf::Result<()> {
        let prf = P::new_from_slice(secret).map_err(|_| kdf::Error)?;
        if !non_secret.is_empty() && !self.summary.has_non_secret {
            // Additional input was provided but isn't used by the context.
            // This is an error
            return Err(kdf::Error);
        }
        if let Some(min_ctr_bits) = self.summary.min_ctr {
            let needed_blocks: usize = out.len().div_ceil(P::output_size());
            let needed_ctr_bits = usize::BITS - needed_blocks.leading_zeros();
            if needed_ctr_bits > min_ctr_bits {
                // We cannot encode the counter in the bits we're given
                return Err(kdf::Error);
            }
        }
        let k0 = if self.summary.has_k0 {
            Some(self.calculate_block(prf.clone(), non_secret, 0, &None, &None, out.len())?)
        } else {
            None
        };

        let mut feedback = None;
        let mut counter = 1;
        let mut data_written = 0;
        while data_written < out.len() {
            let block =
                self.calculate_block(prf.clone(), non_secret, counter, &feedback, &k0, out.len())?;
            let data_to_write = block.len().min(out.len() - data_written);
            out[data_written..data_written + data_to_write]
                .copy_from_slice(&block[..data_to_write]);
            data_written += data_to_write;
            feedback = Some(block);
            counter += 1;
        }
        Ok(())
    }
}

#[derive(Debug, Copy, Clone, Default)]
struct ContextSummary {
    min_ctr: Option<u32>,
    has_k0: bool,
    has_non_secret: bool,
    first_null_idx: Option<usize>,
    last_non_null_idx: Option<usize>,
}
