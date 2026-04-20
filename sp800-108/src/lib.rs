#![no_std]
#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg"
)]
#![cfg_attr(docsrs, feature(doc_cfg))]

use core::marker::PhantomData;

use digest::{FixedOutput, KeyInit, Update};
use kdf::Kdf;

pub const MAX_CONTEXT_COMPONENTS: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContextComponent<'a> {
    Null,
    BeCtr(u32),
    NonSecret,
    Feedback(&'a [u8]),
    K0,
    ConstantString(&'a str),
    ConstantBytes(&'a [u8]),
    BeLength(usize),
}

#[derive(Debug)]
pub struct NistSp800_108KDF<'a, P>
where
    P: FixedOutput + KeyInit + Clone,
{
    context: [ContextComponent<'a>; MAX_CONTEXT_COMPONENTS],
    phantom: PhantomData<P>,
}

impl<'a, P> NistSp800_108KDF<'a, P>
where
    P: FixedOutput + KeyInit + Clone,
{
    pub fn new(context: &[ContextComponent<'a>]) -> kdf::Result<Self> {
        if context.len() > MAX_CONTEXT_COMPONENTS {
            return Err(kdf::Error);
        }
        let mut result = Self {
            context: [ContextComponent::Null; MAX_CONTEXT_COMPONENTS],
            phantom: PhantomData,
        };
        result.context[0..context.len()].copy_from_slice(context);
        Ok(result)
    }

    fn summarize_context(&self) -> ContextSummary {
        self.context
            .iter()
            .fold(ContextSummary::default(), |mut acc, v| -> ContextSummary {
                match v {
                    ContextComponent::BeCtr(length) => {
                        acc.min_ctr = acc
                            .min_ctr
                            .map_or(Some(*length), |old_length| Some(old_length.min(*length)))
                    }
                    ContextComponent::NonSecret => acc.has_non_secret = true,
                    ContextComponent::K0 => acc.has_k0 = true,
                    _ => (), // NOP,
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
                ContextComponent::BeCtr(length) => {
                    Self::update_be_ctr(&mut prf, counter, length as usize)?
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
    fn derive_key(&self, secret: &[u8], non_secret: &[u8], out: &mut [u8]) -> kdf::Result<()> {
        // TODO: Test limits
        let prf = P::new_from_slice(secret).map_err(|_| kdf::Error)?;
        let summary = self.summarize_context();
        if !non_secret.is_empty() && !summary.has_non_secret {
            // Additional input was provided but isn't used by the context.
            // This is an error
            return Err(kdf::Error);
        }
        if let Some(min_ctr_bits) = summary.min_ctr {
            let needed_blocks: usize = out.len().div_ceil(P::output_size());
            let needed_ctr_bits = usize::BITS - needed_blocks.leading_zeros();
            if needed_ctr_bits > min_ctr_bits {
                // We cannot encode the counter in the bits we're given
                return Err(kdf::Error);
            }
        }
        let k0 = if summary.has_k0 {
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
}
