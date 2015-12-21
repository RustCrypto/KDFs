extern crate rustc_serialize;
extern crate hkdf;

use rustc_serialize::hex::{ToHex,FromHex};
use hkdf::Hkdf;

fn main() {
    let ikm = "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b".from_hex().unwrap();
    let salt = "000102030405060708090a0b0c".from_hex().unwrap();
    let info = "f0f1f2f3f4f5f6f7f8f9".from_hex().unwrap();

    let mut hk = Hkdf::new("SHA-256", &ikm, &salt);
    let okm = hk.derive(&info, 42);

    println!("Vector 1 PRK is {}", hk.prk.to_hex());
    println!("Vector 1 OKM is {}", okm.to_hex());
    println!("Matched with https://tools.ietf.org/html/rfc5869#appendix-A.1");

    let expected = "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865";
    assert_eq!(okm.to_hex(), expected);
}

