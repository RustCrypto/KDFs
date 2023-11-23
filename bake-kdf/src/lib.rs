//! An implementation of bake-kdf, defined in [STB 34.101.66-2014][1].
//!
//! # Usage
//! ```rust
//! use bake_kdf::bake_kdf;
//! let x = vec![0x00; 32];
//! let s = vec![0x00; 8];
//! let c = 0x00;
//! let key = bake_kdf(&x, &s, c).unwrap();
//! ```
//!
//! [1]: https://apmi.bsu.by/assets/files/std/bake-spec19.pdf

#![no_std]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg",
    html_root_url = "https://docs.rs/bake-kdf/0.0.0"
)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

use crate::Error::{InvalidDataSize, InvalidKeyLength};
use belt_hash::digest::FixedOutput;
use belt_hash::{belt_compress, BeltHash, Digest};

#[derive(Clone, Copy, Debug, PartialEq)]
/// bake-kdf errors
pub enum Error {
    /// The length of key is invalid
    InvalidKeyLength,
    /// The length of iv or d is invalid
    InvalidDataSize,
}

/// Helper function for transforming BelT keys and blocks from a byte array
/// to an array of `u32`s.
///
/// # Panics
/// If length of `src` is not equal to `4 * N`.
#[inline(always)]
pub fn to_u32<const N: usize>(src: &[u8]) -> [u32; N] {
    assert_eq!(src.len(), 4 * N);
    let mut res = [0u32; N];
    res.iter_mut()
        .zip(src.chunks_exact(4))
        .for_each(|(dst, src)| *dst = u32::from_le_bytes(src.try_into().unwrap()));
    res
}

/// Key expand algorithm described in STB 34.101.34-2020 8.1.2
///
/// Input data:
/// Expandable key: K_1 || K_2 || ... || K_n,
///
/// where K_i is 32-bit word
/// n = 4, 6, 8
///
/// Output data:
/// Expanded key: K 256-bit word
pub fn belt_keyexpand(k: &[u32]) -> Result<[u32; 8], Error> {
    match k.len() {
        // if n = 4, then K = K_1 || K_2 || K_3 || K_4 || K_1 || K_2 || K_3 || K_4
        4 => Ok([k[0], k[1], k[2], k[3], k[0], k[1], k[2], k[3]]),
        // if n = 6, then K = K_1 || K_2 || K_3 || K_4 || K_5 || K_6 || K_1 ^ K_3 || K_2 ^ K_4 || K_3 ^ K_5 || K_4 ^ K_6
        6 => Ok([
            k[0],
            k[1],
            k[2],
            k[3],
            k[4],
            k[5],
            k[0] ^ k[1] ^ k[2],
            k[3] ^ k[4] ^ k[5],
        ]),
        // if n = 8, then K = K_1 || K_2 || K_3 || K_4 || K_5 || K_6 || K_7 || K_8
        8 => Ok([k[0], k[1], k[2], k[3], k[4], k[5], k[6], k[7]]),
        // otherwise, return error
        _ => Err(InvalidKeyLength),
    }
}

/// Key repetition algorithm described in STB 34.101.34-2020 8.1.3
/// Input data:
/// Expanded key: K = K_1 || K_2 || ... || K_n,
/// where K_i is 32-bit word
/// n = 4, 6, 8
/// Data: D = D_1 || D_2 || D_3,
/// where D_i is 32-bit word
/// Initialization vector: I = I_1 || I_2 || I_3 || I_4,
/// where I_i is 32-bit word
/// Output data:
/// Repetition key: Y = Y_1 || Y_2 || ... || Y_n,
/// where Y_i is 32-bit word
pub fn belt_keyrep<const M: usize>(
    x: &[u32],
    d: &[u32],
    i: &[u32],
    out: &mut [u32],
) -> Result<(), Error> {
    let n = x.len() * 32;
    if (n != 128) && (n != 192) && (n != 256) && (M != 128) && (M != 192) && (M != 256) {
        return Err(InvalidKeyLength);
    }
    if d.len() != 3 || i.len() != 4 {
        return Err(InvalidDataSize);
    }

    let r: u32 = match (n, M) {
        (128, 128) => 0xC8BA94B1,
        (192, 128) => 0x12D6E35B,
        (192, 192) => 0xFFC0B05C,
        (256, 128) => 0x1ADC2BE1,
        (256, 192) => 0x3876ABC1,
        (256, 256) => 0x7B653CF3,
        _ => unreachable!(),
    };

    let s = belt_keyexpand(x).map_err(|_| InvalidKeyLength)?;
    let mut d = [d[0], d[1], d[2]];
    let mut i = [i[0], i[1], i[2], i[3]];

    d.iter_mut().for_each(|x| *x = u32::swap_bytes(*x));
    i.iter_mut().for_each(|x| *x = u32::swap_bytes(*x));

    let (_, s) = belt_compress([r, d[0], d[1], d[2]], i, s);

    match M {
        128 => {
            let mut y = [s[0], s[1], s[2], s[3]];
            y.iter_mut().for_each(|x| *x = u32::swap_bytes(*x));
            out.copy_from_slice(&y);
        }
        192 => {
            let mut y = [s[0], s[1], s[2], s[3], s[4], s[5]];
            y.iter_mut().for_each(|x| *x = u32::swap_bytes(*x));
            out.copy_from_slice(&y);
        }
        256 => {
            let mut y = [s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]];
            y.iter_mut().for_each(|x| *x = u32::swap_bytes(*x));
            out.copy_from_slice(&y);
        }
        _ => unreachable!(),
    }

    Ok(())
}

/// bake-kdf algorithm described in STB 34.101.66-2014 8.1.4
pub fn bake_kdf(x: &[u8], s: &[u8], c: u128) -> Result<[u32; 8], Error> {
    let mut hasher = BeltHash::default();
    hasher.update(x);
    hasher.update(s);
    let y = hasher.finalize_fixed();

    let d: [u32; 3] = [0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF];

    let mut c = to_u32::<4>(&c.to_be_bytes());
    c.reverse();

    let mut out = [0u32; 8];
    belt_keyrep::<256>(&to_u32::<8>(&y), &d, &c, &mut out)?;
    Ok(out)
}
