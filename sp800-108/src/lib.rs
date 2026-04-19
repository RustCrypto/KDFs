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
    BeCtr(usize),
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

    fn calculate_block(
        &self,
        mut prf: P,
        non_secret: &[u8],
        counter: u64,
        feedback: &Option<digest::Output<P>>,
        k0: &Option<digest::Output<P>>,
    ) -> kdf::Result<digest::Output<P>> {
        for c in &self.context {
            match c {
                ContextComponent::Null => (),
                ContextComponent::BeCtr(length) => Self::update_be_ctr(&mut prf, counter, *length)?,
                ContextComponent::NonSecret => Update::update(&mut prf, non_secret),
                ContextComponent::Feedback(iv) => Self::update_option(&mut prf, feedback, *iv),
                ContextComponent::K0 => Self::update_option(&mut prf, k0, &[]),
                ContextComponent::ConstantString(value) => {
                    Update::update(&mut prf, value.as_bytes())
                }
                ContextComponent::ConstantBytes(value) => Update::update(&mut prf, value),
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
            Update::update(prf, &data);
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
        let prf = P::new_from_slice(secret).map_err(|_| kdf::Error)?;
        let requires_k0 = self.context.iter().any(|c| c == &ContextComponent::K0);
        let k0 = if requires_k0 {
            Some(self.calculate_block(prf.clone(), non_secret, 0, &None, &None)?)
        } else {
            None
        };

        let mut feedback = None;
        let mut counter = 1;
        let mut data_written = 0;
        while data_written < out.len() {
            let block = self.calculate_block(prf.clone(), non_secret, counter, &feedback, &k0)?;
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

#[cfg(test)]
mod smoke_tests {

    use hex_literal::hex;
    use hmac::Hmac;
    use kdf::Kdf;
    use sha1::Sha1;

    use crate::{NistSp800_108KDF, ContextComponent};

    #[test]
    fn smoke1() {
        let key = hex!("a510fe5ad1640d345a6dbba65d629c2a2fedd1ae");
        let fixed_input = hex!(
            "9953de43418a85aa8db2278a1e380e83fb1e47744d902e8f0d1b3053f185bbcc734d12f219576e75477d7f7b799b7afed1a4847730be8fd2ef3f342e"
        );
        let expected = hex!("c00707a18c57acdb84f17ef05a322da2");
        let context = [
            ContextComponent::BeCtr(16),
            ContextComponent::ConstantBytes(&fixed_input),
        ];
        let kdf: NistSp800_108KDF<Hmac<Sha1>> = NistSp800_108KDF::new(&context).unwrap();

        let mut result = [0u8; 16];
        kdf.derive_key(&key, &[], &mut result).unwrap();
        assert_eq!(result, expected);

        let context = [ContextComponent::BeCtr(16), ContextComponent::NonSecret];
        let kdf: NistSp800_108KDF<Hmac<Sha1>> = NistSp800_108KDF::new(&context).unwrap();

        let mut result = [0u8; 16];
        kdf.derive_key(&key, &fixed_input, &mut result).unwrap();
        assert_eq!(result, expected);
    }

    #[test]
    fn smoke2() {
        let fixed_input = hex!(
            "4b10500ba5c9391da83d2ef78d01bcdccda32ff6f242960323324474b9d0685d99dc9143ac6d667a5b46dcc89784b3a4af7a7684b01efee41b144f48"
        );
        let key = hex!("1ee222f5cdd60b0ae956eeeaa838c51bd767672c");
        let expected = hex!("806e342013853083a3f7294c63a9ec9a6dba75b256c62fac1e480ef26276cd4b");
        let context = [
            ContextComponent::BeCtr(8),
            ContextComponent::ConstantBytes(&fixed_input),
        ];
        let kdf: NistSp800_108KDF<Hmac<Sha1>> = NistSp800_108KDF::new(&context).unwrap();

        let mut result = [0u8; 32];
        kdf.derive_key(&key, &[], &mut result).unwrap();
        assert_eq!(result, expected);

        let context = [ContextComponent::BeCtr(8), ContextComponent::NonSecret];
        let kdf: NistSp800_108KDF<Hmac<Sha1>> = NistSp800_108KDF::new(&context).unwrap();

        let mut result = [0u8; 32];
        kdf.derive_key(&key, &fixed_input, &mut result).unwrap();
        assert_eq!(result, expected);
    }
}
