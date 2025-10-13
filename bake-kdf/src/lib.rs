#![no_std]
#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg"
)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

use belt_hash::digest::FixedOutput;
use belt_hash::{BeltHash, Digest, block_api::belt_compress};

/// `belt-keyexpand` key expansion algorithm described in STB 34.101.34-2020 8.1.2.
///
/// # Panics
/// If `N` is not equal to 16, 24, or 32.
// TODO: use compile-time checks for `N`
#[inline]
pub fn belt_keyexpand<const N: usize>(k: &[u8; N]) -> [u32; 8] {
    let mut t = [0u32; 8];
    // TODO: move this conversion into `belt_keyrep` when we will be able
    // to use generic parameters as `[u32; N / 4]`.
    for (src, dst) in k.chunks_exact(4).zip(t.iter_mut()) {
        *dst = u32::from_le_bytes(src.try_into().unwrap());
    }
    match N {
        16 => {
            t[4] = t[0];
            t[5] = t[1];
            t[6] = t[2];
            t[7] = t[3];
        }
        24 => {
            t[6] = t[0] ^ t[1] ^ t[2];
            t[7] = t[3] ^ t[4] ^ t[5];
        }
        32 => {}
        _ => panic!("Invalid key size n={N}. Expected 16, 24, or 32."),
    }
    t
}

/// `belt-keyrep` key repetition algorithm described in STB 34.101.34-2020 8.1.3.
///
/// # Panics
/// If `(N, M)` is not equal to `(16, 16)`, `(24, 16)`, `(24, 24)`,
/// `(32, 16)`, `(32, 24)`, or `(32, 32)`.
// TODO: use compile-time check for `N` and `M`
#[inline]
pub fn belt_keyrep<const N: usize, const M: usize>(
    x: &[u8; N],
    d: &[u8; 12],
    i: &[u8; 16],
) -> [u8; M] {
    let r: u32 = match (N, M) {
        (16, 16) => 0xC8BA94B1,
        (24, 16) => 0x12D6E35B,
        (24, 24) => 0xFFC0B05C,
        (32, 16) => 0x1ADC2BE1,
        (32, 24) => 0x3876ABC1,
        (32, 32) => 0x7B653CF3,
        _ => panic!("belt-keyrep: invalid combination of N ({N}) and M ({M})"),
    };

    let s = belt_keyexpand(x);

    let d = [
        u32::from_le_bytes(d[..4].try_into().unwrap()),
        u32::from_le_bytes(d[4..][..4].try_into().unwrap()),
        u32::from_le_bytes(d[8..][..4].try_into().unwrap()),
    ];

    let i = [
        u32::from_le_bytes(i[0..][..4].try_into().unwrap()),
        u32::from_le_bytes(i[4..][..4].try_into().unwrap()),
        u32::from_le_bytes(i[8..][..4].try_into().unwrap()),
        u32::from_le_bytes(i[12..][..4].try_into().unwrap()),
    ];

    let (_, s) = belt_compress([r, d[0], d[1], d[2]], i, s);

    let mut y = [0u8; M];
    for (src, dst) in s.iter().zip(y.chunks_exact_mut(4)) {
        dst.copy_from_slice(&src.to_le_bytes());
    }
    y
}

/// `bake-kdf` key derivation algorithm described in STB 34.101.66-2014 8.1.4.
#[inline]
pub fn bake_kdf(x: &[u8], s: &[u8], c: u128) -> [u8; 32] {
    let mut hasher = BeltHash::default();
    hasher.update(x);
    hasher.update(s);
    let y = hasher.finalize_fixed().0;

    belt_keyrep(&y, &[0xFF; 12], &c.to_le_bytes())
}
