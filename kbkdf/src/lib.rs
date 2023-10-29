//! An implementation of KBKDF, the (Key Based Key Derivation Function.
//!
//! This function is described in section 4 of [NIST SP 800-108r1, Recommendation
//! for Key Derivation Using Pseudorandom Functions][1]
//!
//! [1]: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-108r1.pdf

#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]

#[cfg(feature = "std")]
extern crate std;

use core::{fmt, marker::PhantomData, num::Wrapping, ops::Mul};
use digest::{
    consts::{U32, U8},
    crypto_common::KeySizeUser,
    generic_array::{typenum::Unsigned, ArrayLength, GenericArray},
    typenum::op,
    KeyInit, Mac,
};
use divrem::DivCeil;

mod sealed;

#[derive(Debug, PartialEq)]
pub enum Error {
    // TODO(baloo): we can probably move that to a compilation error via use of typenum
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

#[cfg(feature = "std")]
mod std_error {
    use super::Error;
    use std::error;

    impl error::Error for Error {}
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
    OutputLen: ArrayLength<u8> + Mul<U8>,
    <OutputLen as Mul<U8>>::Output: Unsigned,
    PrfOutputLen: ArrayLength<u8> + Mul<U8>,
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
    K::KeySize: ArrayLength<u8> + Mul<U8>,
    <K::KeySize as Mul<U8>>::Output: Unsigned,
    Prf::OutputSize: ArrayLength<u8> + Mul<U8>,
    <Prf::OutputSize as Mul<U8>>::Output: Unsigned,
{
    /// Derives `key` from `kin` and other parameters.
    fn derive(
        &self,
        kin: &GenericArray<u8, Prf::KeySize>,
        use_l: bool,
        use_separator: bool,
        label: &[u8],
        context: &[u8],
    ) -> Result<GenericArray<u8, K::KeySize>, Error> {
        // n - An integer whose value is the number of iterations of the PRF needed to generate L
        // bits of keying material
        let n: u32 = Wrapping(<KbkdfCore<K::KeySize, Prf::OutputSize> as KbkdfUser>::L::U32)
            .div_ceil(Wrapping(
                <KbkdfCore<K::KeySize, Prf::OutputSize> as KbkdfUser>::H::U32,
            ))
            .0;

        if n as usize > 2usize.pow(R::U32) - 1 {
            return Err(Error::InvalidRequestSize);
        }

        let mut output = GenericArray::<u8, K::KeySize>::default();
        let mut builder = output.as_mut_slice();

        let mut ki = None;
        self.input_iv(&mut ki);

        for counter in 1..=n {
            let mut h = <Prf as Mac>::new(kin);

            if Self::FEEDBACK_KI {
                if let Some(ki) = ki {
                    h.update(ki.as_slice());
                }
            }

            // counter encoded as big endian u32
            // Type parameter R encodes how large the value is to be (either U8, U16, U24, or U32)
            //
            // counter = 1u32 ([0, 0, 0, 1])
            //                     \-------/
            //                      R = u24
            h.update(&counter.to_be_bytes()[(4 - R::USIZE / 8)..]);

            // Fixed input data
            h.update(label);
            if use_separator {
                h.update(&[0]);
            }
            h.update(context);
            if use_l {
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
    fn input_iv(&self, _ki: &mut Option<GenericArray<u8, Prf::OutputSize>>) {}

    /// Whether the KI should be reinjected every round.
    const FEEDBACK_KI: bool = false;
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
    K::KeySize: ArrayLength<u8> + Mul<U8>,
    <K::KeySize as Mul<U8>>::Output: Unsigned,
    Prf::OutputSize: ArrayLength<u8> + Mul<U8>,
    <Prf::OutputSize as Mul<U8>>::Output: Unsigned,
    R: sealed::R,
{
}

pub struct Feedback<'a, Prf, K, R = U32>
where
    Prf: Mac,
{
    iv: Option<&'a GenericArray<u8, Prf::OutputSize>>,
    _marker: PhantomData<(Prf, K, R)>,
}

impl<'a, Prf, K, R> Feedback<'a, Prf, K, R>
where
    Prf: Mac,
{
    pub fn new(iv: Option<&'a GenericArray<u8, Prf::OutputSize>>) -> Self {
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
    K::KeySize: ArrayLength<u8> + Mul<U8>,
    <K::KeySize as Mul<U8>>::Output: Unsigned,
    Prf::OutputSize: ArrayLength<u8> + Mul<U8>,
    <Prf::OutputSize as Mul<U8>>::Output: Unsigned,
    R: sealed::R,
{
    fn input_iv(&self, ki: &mut Option<GenericArray<u8, Prf::OutputSize>>) {
        if let Some(iv) = self.iv {
            *ki = Some(iv.clone())
        }
    }

    const FEEDBACK_KI: bool = true;
}

#[cfg(test)]
mod tests {
    use super::{Counter, Feedback, GenericArray, Kbkdf};
    use digest::consts::*;
    use hex_literal::hex;

    #[derive(Debug)]
    struct KnownValue {
        key: &'static [u8],
        iv: Option<&'static [u8]>,
        use_l: bool,
        label: &'static [u8],
        context: &'static [u8],
        use_separator: bool,
        expected: &'static [u8],
    }

    static KNOWN_VALUES_COUNTER_HMAC_SHA256: &[KnownValue] = &[
        KnownValue {
            iv: None,
            use_l: false,
            use_separator: false,
            label: &[],
            context: &[],
            key: &hex!(
                "
                241C3FBAABEDE87601B1C778B24F9A32 742A14FE34DA61D77E8352EF9D6C7FC8
                E335E32344E21D7DC0CD627D7E2FF973 992611F372C5D3DD91C100F2C6DB2CAF
            "
            ),
            expected: &hex!(
                "
                0FBF4313B2F1AF1F98C9763FE7F816CD 6464234F7C524F0C4ACDF66F287B01EB
                82D3A90CEF26EE996EE4F0295FA7FA36 1E2E85DC710A236974E1ABBC342F4E23
                D9A8F6B1ADC4C48332C5ED88C42FDCFB BA34CF70F1EA599908FBE35E2C121E0D
                BFD94D45C70FC9D9CCB899E439D21F88 D3924EF5EC8613E5C386DE7B22427FC4
            "
            ),
        },
        KnownValue {
            iv: None,
            use_l: true,
            use_separator: true,
            label: &[0x22, 0x33],
            context: &[0x0, 0x11],
            key: &hex!(
                "
                241C3FBAABEDE87601B1C778B24F9A32 742A14FE34DA61D77E8352EF9D6C7FC8
                E335E32344E21D7DC0CD627D7E2FF973 992611F372C5D3DD91C100F2C6DB2CAF
            "
            ),
            expected: &hex!(
                "
                7F21415C8ED32102BE3C284E970B3DF4 5FCE9F7464FC6616ED59AC1F1ECA0565
                8E2868C57974293A79D49B576C4083C3 48AD07508E8A673D0F6B496ED444E0DE
                80AE1F146F8C2CBFE09F1D04516338DE 9E5284236FE29CB2D71A183B7573DFE7
                0A8321ADAAF6FC2EDC73C228289948DD 3230D56E7A9103E2736957B326ACE921
            "
            ),
        },
    ];

    static KNOWN_VALUES_FEEDBACK_HMAC_SHA256: &[KnownValue] = &[
        KnownValue {
            iv: Some(b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
            use_l: true,
            use_separator: true,
            label: &[0x22, 0x33],
            context: &[0x0, 0x11],
            key: &hex!(
                "
                241C3FBAABEDE87601B1C778B24F9A32 742A14FE34DA61D77E8352EF9D6C7FC8
                E335E32344E21D7DC0CD627D7E2FF973 992611F372C5D3DD91C100F2C6DB2CAF
            "
            ),
            expected: &hex!(
                "
                C8C8E79188DB5732B52F81111E2982BD 479865EF98E90A823926BC0EA1EB173B
                21CA03B80228A6A1E27BE64DA382F1B7 ADFF97CF43598AF2435827B2F6E78DD5
                F9CBCC4948775451AD2BD44A9DBE2EE4 6FA5A73463E10142A3A1228183B45BC8
                D3831AA13EED6F94E8F221FACBC80F8B D19BDF06EC82DE7AE0FE0EE37CA51FF2
            "
            ),
        },
        KnownValue {
            iv: None,
            use_l: true,
            use_separator: true,
            label: &[0x22, 0x33],
            context: &[0x0, 0x11],
            key: &hex!(
                "
                241C3FBAABEDE87601B1C778B24F9A32 742A14FE34DA61D77E8352EF9D6C7FC8
                E335E32344E21D7DC0CD627D7E2FF973 992611F372C5D3DD91C100F2C6DB2CAF
            "
            ),
            expected: &hex!(
                "
                7F21415C8ED32102BE3C284E970B3DF4 5FCE9F7464FC6616ED59AC1F1ECA0565
                B0BDCC163BF8119490B0B82715FF3EF1 B52DF9A81BC836BA6FC5168C08CE837B
                0CB7C18D1C47459DF6A05C16C140109E 8FC15D0EC9541FC41E127EBBDBC48CDE
                93E8909855F9070E9B709A497D31A825 3E3CB4EEB1C18586277B2F76E4BF9FF0
            "
            ),
        },
    ];

    #[test]
    fn test_static_values_counter() {
        type HmacSha256 = hmac::Hmac<sha2::Sha256>;
        type HmacSha512 = hmac::Hmac<sha2::Sha512>;

        let counter = Counter::<HmacSha256, HmacSha512>::default();
        for (v, i) in KNOWN_VALUES_COUNTER_HMAC_SHA256.iter().zip(0..) {
            assert_eq!(
                counter.derive(
                    GenericArray::from_slice(v.key),
                    v.use_l,
                    v.use_separator,
                    v.label,
                    v.context,
                ),
                Ok(GenericArray::<_, U128>::from_slice(v.expected).clone()),
                "key derivation failed for (index: {i}):\n{v:x?}"
            );
        }
    }

    #[test]
    fn test_static_values_feedback() {
        type HmacSha256 = hmac::Hmac<sha2::Sha256>;
        type HmacSha512 = hmac::Hmac<sha2::Sha512>;

        for (v, i) in KNOWN_VALUES_FEEDBACK_HMAC_SHA256.iter().zip(0..) {
            let feedback =
                Feedback::<HmacSha256, HmacSha512>::new(v.iv.map(GenericArray::from_slice));
            assert_eq!(
                feedback.derive(
                    GenericArray::from_slice(v.key),
                    v.use_l,
                    v.use_separator,
                    v.label,
                    v.context,
                ),
                Ok(GenericArray::<_, U128>::from_slice(v.expected).clone()),
                "key derivation failed for (index: {i}):\n{v:x?}"
            );
        }
    }
}
