use digest::consts::*;
use kbkdf::{Kbkdf, Params};

use core::{convert::TryInto, ops::Mul};
use digest::{
    KeyInit, Mac,
    array::{ArraySize, typenum::Unsigned},
    common::KeySizeUser,
};

use crate::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Prf {
    CmacAes128,
    CmacAes192,
    CmacAes256,
    CmacTdes2,
    CmacTdes3,
    HmacSha1,
    HmacSha224,
    HmacSha256,
    HmacSha384,
    HmacSha512,
}

impl Prf {
    fn from_str(s: &str) -> Self {
        match s {
            "[PRF=CMAC_AES128]" => Self::CmacAes128,
            "[PRF=CMAC_AES192]" => Self::CmacAes192,
            "[PRF=CMAC_AES256]" => Self::CmacAes256,
            "[PRF=CMAC_TDES2]" => Self::CmacTdes2,
            "[PRF=CMAC_TDES3]" => Self::CmacTdes3,
            "[PRF=HMAC_SHA1]" => Self::HmacSha1,
            "[PRF=HMAC_SHA224]" => Self::HmacSha224,
            "[PRF=HMAC_SHA256]" => Self::HmacSha256,
            "[PRF=HMAC_SHA384]" => Self::HmacSha384,
            "[PRF=HMAC_SHA512]" => Self::HmacSha512,
            _ => panic!("Invalid prf: {s}"),
        }
    }

    fn is_supported(&self) -> bool {
        let not_supported = matches!(self, Self::CmacTdes2 | Self::CmacTdes3);
        !not_supported
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CounterLocation {
    Before,
    Middle,
    After,
    BeforeIter,
    AfterIter,
}

impl CounterLocation {
    fn from_str(s: &str) -> Self {
        match s {
            "[CTRLOCATION=BEFORE_FIXED]" => Self::Before,
            "[CTRLOCATION=MIDDLE_FIXED]" => Self::Middle,
            "[CTRLOCATION=AFTER_FIXED]" => Self::After,
            "[CTRLOCATION=AFTER_ITER]" => Self::AfterIter,
            "[CTRLOCATION=BEFORE_ITER]" => Self::BeforeIter,
            _ => panic!("Invalid counter_location: {s}"),
        }
    }

    fn is_supported(&self) -> bool {
        matches!(self, Self::Before | Self::AfterIter)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Rlen {
    Bits8,
    Bits16,
    Bits24,
    Bits32,
}

impl Rlen {
    fn from_str(s: &str) -> Self {
        match s {
            "[RLEN=8_BITS]" => Self::Bits8,
            "[RLEN=16_BITS]" => Self::Bits16,
            "[RLEN=24_BITS]" => Self::Bits24,
            "[RLEN=32_BITS]" => Self::Bits32,
            _ => panic!("Invalid r_len: {s}"),
        }
    }
}

/// Each trait implementation represents one KBKDF mode and its data.
trait TestData {
    /// Returns the expected output length of the output key.
    fn l(&self) -> usize;

    /// Reads test data from the iterator over test data file.
    fn read_test_data<'a>(lines: impl Iterator<Item = &'a str>, ctx: CounterLocation) -> Self;

    /// Executes KBKDF key derivation.
    fn test_kbkdf<Prf, K, R>(&self, use_counter: bool)
    where
        Prf: Mac + KeyInit,
        K: KeySizeUser,
        K::KeySize: ArraySize + Mul<U8>,
        <K::KeySize as Mul<U8>>::Output: Unsigned,
        Prf::OutputSize: ArraySize + Mul<U8>,
        <Prf::OutputSize as Mul<U8>>::Output: Unsigned,
        R: kbkdf::sealed::R;
}

struct CounterTestData {
    l: usize,
    ki: Vec<u8>,
    fixed_data: (Vec<u8>, Vec<u8>),
    ko: Vec<u8>,
}

impl TestData for CounterTestData {
    fn l(&self) -> usize {
        self.l
    }

    fn read_test_data<'a>(
        mut data: impl Iterator<Item = &'a str>,
        counter_location: CounterLocation,
    ) -> Self {
        // L = ...
        let l = data.next().unwrap()[4..].parse().unwrap();
        // KI = ...
        let ki = hex::decode(&data.next().unwrap()[5..]).unwrap();

        let fixed_data = if let CounterLocation::Middle = counter_location {
            // Skip "DataBeforeCtrLen"
            data.next();
            let before_counter = hex::decode(&data.next().unwrap()[19..]).unwrap();

            // Skip "DataAfterCtrLen"
            data.next();
            let after_counter = hex::decode(&data.next().unwrap()[18..]).unwrap();

            (before_counter, after_counter)
        } else {
            // Skip "FixedInputDataByteLen".
            data.next();
            let fixed_input_data = hex::decode(&data.next().unwrap()[17..]).unwrap();

            (fixed_input_data, Vec::new())
        };
        let ko = hex::decode(&data.next().unwrap()[5..]).unwrap();

        Self {
            l,
            ki,
            fixed_data,
            ko,
        }
    }

    fn test_kbkdf<Prf, K, R>(&self, use_counter: bool)
    where
        Prf: Mac + KeyInit,
        K: KeySizeUser,
        K::KeySize: ArraySize + Mul<U8>,
        <K::KeySize as Mul<U8>>::Output: Unsigned,
        Prf::OutputSize: ArraySize + Mul<U8>,
        <Prf::OutputSize as Mul<U8>>::Output: Unsigned,
        R: kbkdf::sealed::R,
    {
        let counter = kbkdf::Counter::<Prf, K, R>::default();

        let (label, context) = &self.fixed_data;

        let key = counter
            .derive(
                Params::builder(self.ki.as_slice())
                    .use_l(false)
                    .use_separator(false)
                    .use_counter(use_counter)
                    .with_label(label.as_slice())
                    .with_context(context.as_slice())
                    .build(),
            )
            .unwrap();

        assert_eq!(self.ko[..], key[..]);
    }
}

struct DoublePipelineTestData {
    l: usize,
    ki: Vec<u8>,
    fixed_data: Vec<u8>,
    ko: Vec<u8>,
}

impl TestData for DoublePipelineTestData {
    fn read_test_data<'a>(mut data: impl Iterator<Item = &'a str>, _: CounterLocation) -> Self {
        // L = ...
        let l = data.next().unwrap()[4..].parse().unwrap();
        // KI = ...
        let ki = hex::decode(&data.next().unwrap()[5..]).unwrap();

        // Skip "FixedInputDataByteLen".
        data.next();
        let fixed_data = hex::decode(&data.next().unwrap()[17..]).unwrap();

        let ko = hex::decode(&data.next().unwrap()[5..]).unwrap();

        Self {
            l,
            ki,
            fixed_data,
            ko,
        }
    }

    fn test_kbkdf<Prf, K, R>(&self, use_counter: bool)
    where
        Prf: Mac + KeyInit,
        K: KeySizeUser,
        K::KeySize: ArraySize + Mul<U8>,
        <K::KeySize as Mul<U8>>::Output: Unsigned,
        Prf::OutputSize: ArraySize + Mul<U8>,
        <Prf::OutputSize as Mul<U8>>::Output: Unsigned,
        R: kbkdf::sealed::R,
    {
        let double_pipeline = kbkdf::DoublePipeline::<Prf, K, R>::default();

        let key = double_pipeline
            .derive(
                Params::builder(self.ki.as_slice())
                    .use_l(false)
                    .use_separator(false)
                    .use_counter(use_counter)
                    .with_label(self.fixed_data.as_slice())
                    .build(),
            )
            .unwrap();

        assert_eq!(self.ko[..], key[..]);
    }

    fn l(&self) -> usize {
        self.l
    }
}

struct FeedbackTestData {
    l: usize,
    ki: Vec<u8>,
    iv: Vec<u8>,
    fixed_data: Vec<u8>,
    ko: Vec<u8>,
}

impl TestData for FeedbackTestData {
    fn read_test_data<'a>(mut data: impl Iterator<Item = &'a str>, _: CounterLocation) -> Self {
        // L = ...
        let l = data.next().unwrap()[4..].parse().unwrap();
        // KI = ...
        let ki = hex::decode(&data.next().unwrap()[5..]).unwrap();

        // Skip "IVlen"
        data.next();
        // IV = ...
        let iv = hex::decode(&data.next().unwrap()[5..]).unwrap();

        // Skip "FixedInputDataByteLen".
        data.next();
        let fixed_data = hex::decode(&data.next().unwrap()[17..]).unwrap();

        let ko = hex::decode(&data.next().unwrap()[5..]).unwrap();

        Self {
            l,
            ki,
            iv,
            fixed_data,
            ko,
        }
    }

    fn test_kbkdf<Prf, K, R>(&self, use_counter: bool)
    where
        Prf: Mac + KeyInit,
        K: KeySizeUser,
        K::KeySize: ArraySize + Mul<U8>,
        <K::KeySize as Mul<U8>>::Output: Unsigned,
        Prf::OutputSize: ArraySize + Mul<U8>,
        <Prf::OutputSize as Mul<U8>>::Output: Unsigned,
        R: kbkdf::sealed::R,
    {
        let iv = if !self.iv.is_empty() {
            Some(self.iv.as_slice().try_into().unwrap())
        } else {
            None
        };
        let feedback = kbkdf::Feedback::<Prf, K, R>::new(iv);

        let key = feedback
            .derive(
                Params::builder(self.ki.as_slice())
                    .use_l(false)
                    .use_separator(false)
                    .use_counter(use_counter)
                    .with_label(self.fixed_data.as_slice())
                    .build(),
            )
            .unwrap();

        assert_eq!(self.ko[..], key[..]);
    }

    fn l(&self) -> usize {
        self.l
    }
}

// This function tests KBKDF implementation against test vectors parsed from the file.
//
// All KDF parameters are obtained in runtime, but the implementation relies on generic type parameters which are compile-time.
// Macros inside this function generate all possible KDF parameter configurations. A suitable KDF configuration will be selected during runtime.
fn test_kbkdf<T: TestData>(test_data: T, prf: Prf, r_len: Rlen, use_counter: bool) {
    macro_rules! gen_inner {
        ($prf_ty:ident, { $($l_value:expr => $l_ty:ident,)* }, { $($r_value:expr => $r_ty:ident,)* }) => {
            gen_inner!(@inner $prf_ty : $($l_value => $l_ty,)* ; $($r_value => $r_ty,)*);
        };
        (@inner $prf_ty:ident : $next_l_value:expr => $next_l_ty:ident, $($l_value:expr => $l_ty:ident,)* ; $($r_value:expr => $r_ty:ident,)*) => {
            if test_data.l() == $next_l_value {
                $(
                    if r_len == $r_value {
                        test_data.test_kbkdf::<$prf_ty, $next_l_ty, $r_ty>(use_counter);
                        return;
                    }
                )*
            }
            gen_inner!(@inner $prf_ty : $($l_value => $l_ty,)* ; $($r_value => $r_ty,)*);
        };
        (@inner $prf_ty:ident : ; $($r_value:expr => $r_ty:ident,)*) => {};
    }

    macro_rules! gen_test {
        ({ $($prf_value:expr => $prf_ty:ident,)* }, { $($l_value:expr => $l_ty:ident,)* }, { $($r_value:expr => $r_ty:ident,)* }) => {
            gen_test!(@inner $($prf_value => $prf_ty,)* ; $($l_value => $l_ty,)* ; $($r_value => $r_ty,)*);
        };
        (@inner $next_prf_value:expr => $next_prf_ty:ident, $($prf_value:expr => $prf_ty:ident,)* ; $($l_value:expr => $l_ty:ident,)* ; $($r_value:expr => $r_ty:ident,)*) => {
            if prf == $next_prf_value {
                gen_inner!($next_prf_ty, { $($l_value => $l_ty,)* }, { $($r_value => $r_ty,)* });
            }
            gen_test!(@inner $($prf_value => $prf_ty,)* ; $($l_value => $l_ty,)* ; $($r_value => $r_ty,)*);
        };
        (@inner ; $($l_value:expr => $l_ty:ident,)* ; $($r_value:expr => $r_ty:ident,)*) => {};
    }

    gen_test!({
        Prf::CmacAes128 => CmacAes128,
        Prf::CmacAes192 => CmacAes192,
        Prf::CmacAes256 => CmacAes256,
        Prf::HmacSha1 => HmacSha1,
        Prf::HmacSha224 => HmacSha224,
        Prf::HmacSha256 => HmacSha256,
        Prf::HmacSha384 => HmacSha384,
        Prf::HmacSha512 => HmacSha512,
    }, {
        128 => MockOutputU128,
        160 => MockOutputU160,
        256 => MockOutputU256,
        320 => MockOutputU320,
        480 => MockOutputU480,
        512 => MockOutputU512,
        528 => MockOutputU528,
        560 => MockOutputU560,
        1024 => MockOutputU1024,
        1040 => MockOutputU1040,
        1600 => MockOutputU1600,
        2048 => MockOutputU2048,
        2064 => MockOutputU2064,
        2400 => MockOutputU2400,
    }, {
        Rlen::Bits8 => U8,
        Rlen::Bits16 => U16,
        Rlen::Bits24 => U24,
        Rlen::Bits32 => U32,
    });

    panic!(
        "unhandled KBKDF parameters: {:?} {} {:?}",
        prf,
        test_data.l(),
        r_len
    );
}

fn next_line<'a>(mut data: impl Iterator<Item = &'a str>) -> Option<&'a str> {
    Some(loop {
        if let Some(l) = data.next() {
            if !l.is_empty() {
                break l;
            }
        } else {
            return None;
        }
    })
}

/// Parses NIST test vectors and test the KBKDF implementation against them.
///
/// The return value should be ignored. It uses the `Option`type only to
/// get out of the function conveniently when the end of the file is reached.
fn eval_test_vectors<T: TestData>(data: &str, use_counter: bool) -> Option<()> {
    let mut data = data.split("\r\n");

    let mut line = data.next();

    while let Some(l) = line {
        // Skip comments and empty lines.
        if l.starts_with("#") || l.is_empty() {
            line = data.next();
            continue;
        }

        // Read and parse KBKDF configuration.
        let prf = Prf::from_str(l);
        let (counter_location, r_len) = if use_counter {
            (
                CounterLocation::from_str(data.next().unwrap()),
                Rlen::from_str(data.next().unwrap()),
            )
        } else {
            // Counter location and r-len are not needed and do not present in a test file.
            // We any use any values here, because they are ignored anyway
            (CounterLocation::Before, Rlen::Bits8)
        };

        if !prf.is_supported() || !counter_location.is_supported() {
            // Skip unsupported configuration.

            line = loop {
                let next_line = next_line(&mut data)?;
                if next_line.starts_with("[PRF=") {
                    // Reached next KBKDF configuration.
                    break Some(next_line);
                }
            };
        } else {
            let mut count_data = next_line(&mut data);
            while let Some(count) = count_data {
                if count.is_empty() {
                    break;
                }

                // Read test cases data.
                let test_data = T::read_test_data(&mut data, counter_location);

                // Test KBKDF.
                test_kbkdf(test_data, prf, r_len, use_counter);

                let next_line = next_line(&mut data)?;

                if next_line.starts_with("[PRF=") {
                    line = Some(next_line);
                    // Reached the next KBKDF configuration.
                    break;
                } else {
                    // Continue reading test cases.
                    count_data = Some(next_line);
                }
            }
        }
    }

    Some(())
}

#[test]
fn counter_mode() {
    let data = include_str!("../data/CounterMode/KDFCTR_gen.rsp");

    eval_test_vectors::<CounterTestData>(data, true);
}

#[test]
fn feedback_mode_no_zero_iv() {
    let data = include_str!("../data/FeedbackModeNOzeroiv/KDFFeedback_gen.rsp");

    eval_test_vectors::<FeedbackTestData>(data, true);
}

#[test]
fn feedback_mode_with_zero_iv() {
    let data = include_str!("../data/FeedbackModewzeroiv/KDFFeedback_gen.rsp");

    eval_test_vectors::<FeedbackTestData>(data, true);
}

#[test]
fn feedback_mode_without_counter() {
    let data = include_str!("../data/FeedbackModenocounter/KDFFeedback_gen.rsp");

    eval_test_vectors::<FeedbackTestData>(data, false);
}

#[test]
fn pipeline_mode_without_counter() {
    let data = include_str!("../data/PipelineModeWOCounterr/KDFDblPipeline_gen.rsp");

    eval_test_vectors::<DoublePipelineTestData>(data, false);
}

#[test]
fn pipeline_mode_with_counter() {
    let data = include_str!("../data/PipelineModewithCounter/KDFDblPipeline_gen.rsp");

    eval_test_vectors::<DoublePipelineTestData>(data, true);
}
