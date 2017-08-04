extern crate generic_array;
extern crate digest;
extern crate hmac;

#[cfg(test)]
extern crate hex;
#[cfg(test)]
extern crate sha2;

use std::cmp;
use digest::{Input, BlockInput, FixedOutput};
use digest::Digest; // for sizetest=D::new()
use generic_array::{ArrayLength, GenericArray};
use hmac::{Hmac, Mac};

pub struct Hkdf<D>
    where D: Input + BlockInput + FixedOutput + Default,
          D::OutputSize: ArrayLength<u8>
{
    pub prk: GenericArray<u8, D::OutputSize>,
}

impl <D> Hkdf<D>
    where D: Input + BlockInput + FixedOutput + Default,
          D::OutputSize: ArrayLength<u8>
{
    pub fn new(ikm: &[u8], salt: &[u8]) -> Hkdf<D> {
        let mut hmac = Hmac::<D>::new(salt);
        hmac.input(ikm);
        let mut arr = GenericArray::default();
        arr.copy_from_slice(hmac.result().code());
        Hkdf {
            prk: arr,
        }
    }

    pub fn derive(&mut self, info: &[u8], length: usize) -> Vec<u8> {
        let mut okm = Vec::<u8>::with_capacity(length);
        let mut prev = Vec::<u8>::new();

        //if length > <D as FixedOutput>::OutputSize.to_usize() * 255 {
        //if length > D::OutputSize.to_usize() * 255 {
        let sizetest = D::new();
        let hmac_output_bytes = sizetest.fixed_result().len();
        if length > hmac_output_bytes * 255 {
            panic!("Invalid number of blocks, length too large");
        }

        let mut remaining = length;
        let mut blocknum = 1;
        while remaining > 0 {
            let mut output_block = Hmac::<D>::new(&self.prk);
            let c = vec![blocknum as u8];

            output_block.input(&prev);
            output_block.input(&info);
            output_block.input(&c);

            prev = output_block.result().code().to_vec();
            let needed = cmp::min(remaining, hmac_output_bytes);
            okm.extend(&prev[..needed]);
            blocknum += 1;
            remaining -= needed;
        }

        return okm;
    }
}

#[cfg(test)]
mod tests {
    use Hkdf;
    use hex::{ToHex, FromHex};
    use sha2::Sha256;

    struct Test<'a> {
        ikm: &'a str,
        salt: &'a str,
        info: &'a str,
        length: usize,
        prk: &'a str,
        okm: &'a str,
    }

    // Test Vectors from https://tools.ietf.org/html/rfc5869.
    fn tests<'a>() -> Vec<Test<'a>> {
        vec![Test {
                 ikm: "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
                 salt: "000102030405060708090a0b0c",
                 info: "f0f1f2f3f4f5f6f7f8f9",
                 length: 42,
                 prk: "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5",
                 okm: "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b8\
                       87185865",
             },
             Test {
                 ikm: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425\
                       262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b\
                       4c4d4e4f",
                 salt: "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f80818283848\
                        5868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aa\
                        abacadaeaf",
                 info: "b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d\
                        5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fa\
                        fbfcfdfeff",
                 length: 82,
                 prk: "06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244",
                 okm: "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7\
                       827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5\
                       c1f3434f1d87",
             },
             Test {
                 ikm: "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
                 salt: "",
                 info: "",
                 length: 42,
                 prk: "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04",
                 okm: "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4\
                       b61a96c8",
             }]
    }

    #[test]
    fn test_derive() {
        let tests = tests();
        for t in tests.iter() {
            let ikm = &Vec::from_hex(&t.ikm).unwrap()[..];
            let salt = &Vec::from_hex(&t.salt).unwrap()[..];
            let info = &Vec::from_hex(&t.info).unwrap()[..];
            let mut hkdf = Hkdf::<Sha256>::new(ikm, salt);
            let okm = hkdf.derive(info, t.length);

            assert_eq!(hkdf.prk.to_hex(), t.prk);
            assert_eq!(okm.to_hex(), t.okm);
        }
    }

    const MAX_SHA256_LENGTH: usize = 255 * (256 / 8); // =8160

    #[test]
    fn test_lengths() {
        let mut hkdf = Hkdf::<Sha256>::new(&[], &[]);
        let longest = hkdf.derive(&[], MAX_SHA256_LENGTH);
        // Runtime is O(length), so exhaustively testing all legal lengths
        // would take too long (at least without --release). Only test a
        // subset: the first 500, the last 10, and every 100th in between.
        let lengths = (0..MAX_SHA256_LENGTH + 1).filter(|&len| {
            len < 500 || len > MAX_SHA256_LENGTH - 10 || len % 100 == 0
        });

        for length in lengths {
            let okm = hkdf.derive(&[], length);
            assert_eq!(okm.len(), length);
            assert_eq!(okm.to_hex(), longest[..length].iter().to_hex());
        }
    }

    #[test]
    fn test_max_length() {
        let mut hkdf = Hkdf::<Sha256>::new(&[], &[]);
        hkdf.derive(&[], MAX_SHA256_LENGTH);
    }

    #[test]
    #[should_panic(expected="length too large")]
    fn test_max_length_exceeded() {
        let mut hkdf = Hkdf::<Sha256>::new(&[], &[]);
        hkdf.derive(&[], MAX_SHA256_LENGTH + 1);
    }

    #[test]
    #[should_panic]
    fn test_unsupported_length() {
        let mut hkdf = Hkdf::<Sha256>::new(&[], &[]);
        hkdf.derive(&[], 90000);
    }
}
