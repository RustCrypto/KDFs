extern crate hex;
extern crate hkdf;
extern crate sha2;

use sha2::Sha256;
use hex::{ToHex,FromHex};
use hkdf::Hkdf;

fn main() {
    let ikm = Vec::from_hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
    let salt = Vec::from_hex("000102030405060708090a0b0c").unwrap();
    let info = Vec::from_hex("f0f1f2f3f4f5f6f7f8f9").unwrap();

    let mut hk = Hkdf::<Sha256>::new(&ikm, &salt);
    let okm = hk.derive(&info, 42);

    println!("Vector 1 PRK is {}", hk.prk.to_hex());
    println!("Vector 1 OKM is {}", okm.to_hex());
    println!("Matched with https://tools.ietf.org/html/rfc5869#appendix-A.1");

    let expected = "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865";
    assert_eq!(okm.to_hex(), expected);
}

