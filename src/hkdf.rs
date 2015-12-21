extern crate crypto;
extern crate rustc_serialize;

use crypto::hmac;
use crypto::digest::Digest;
use crypto::mac::Mac;
use crypto::sha2::Sha256;

pub struct Hkdf {
    pub prk: Vec<u8>,
    pub block_size: usize
}

impl Hkdf {
    pub fn new(digest: &str, ikm: &[u8], salt: &[u8]) -> Hkdf {
        let alg = match digest {
            "SHA-256" => Sha256::new(),
            _ => panic!("Hashing algorithm not supported")
        };

        let mut hmac = hmac::Hmac::new(alg, salt);
        hmac.input(ikm);

        Hkdf {
            prk: hmac.result().code().to_vec(),
            block_size: alg.block_size()
        }
    }

    pub fn derive(&mut self, info: &[u8], length: usize) -> Vec<u8> {
        let block_size = self.block_size;
        let remain = if length % block_size == 0 {
            0
        } else {
            1
        };

        let blocks_needed = length / block_size + remain;
        let mut okm = Vec::<u8>::new();
        let mut prev = Vec::<u8>::new();

        if blocks_needed > 255 {
            panic!("Invalid number of blocks, length too large");
        }

        for n in 0..blocks_needed+1 {
            let mut output_block = hmac::Hmac::new(Sha256::new(), &self.prk);
            let c = vec![(n + 1) as u8];

            output_block.input(&prev);
            output_block.input(&info);
            output_block.input(&c);

            prev = output_block.result().code().to_vec();
            okm.extend(&prev);
        }

        let mut result = Vec::<u8>::new();
        result.extend(&okm[..length]);

        return result;
    }
}

#[cfg(test)]
mod tests {
    use Hkdf;
    use rustc_serialize::hex::{ToHex,FromHex};

    struct Test {
        digest: String,
        ikm: String,
        salt: String,
        info: String,
        length: usize,
        prk: String,
        okm: String
    }

    // Test Vectors from https://tools.ietf.org/html/rfc5869.
    fn tests() -> Vec<Test> {
        vec![
            Test {
                digest: "SHA-256".to_string(),
                ikm: "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b".to_string(),
                salt: "000102030405060708090a0b0c".to_string(),
                info: "f0f1f2f3f4f5f6f7f8f9".to_string(),
                length: 42,
                prk: "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5".to_string(),
                okm: "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865".to_string()
            },
            Test {
                digest: "SHA-256".to_string(),
                ikm: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f".to_string(),
                salt: "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf".to_string(),
                info: "b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff".to_string(),
                length: 82,
                prk: "06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244".to_string(),
                okm: "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87".to_string()
            },
            Test {
                digest: "SHA-256".to_string(),
                ikm: "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b".to_string(),
                salt: "".to_string(),
                info: "".to_string(),
                length: 42,
                prk: "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04".to_string(),
                okm: "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8".to_string()
            }
        ]
    }

    #[test]
    fn test_derive() {
        let tests = tests();
        for t in tests.iter() {
            let mut hkdf = Hkdf::new(
                &t.digest,
                &t.ikm.from_hex().unwrap(),
                &t.salt.from_hex().unwrap()
            );

            let okm = hkdf.derive(
                &t.info.from_hex().unwrap(),
                t.length
            );

            assert_eq!(hkdf.prk.to_hex(), t.prk);
            assert_eq!(okm.to_hex(), t.okm);
        }
    }

    #[test]
    #[should_panic]
    fn test_unsupported_digest() {
        Hkdf::new("SHA-1337", &[], &[]);
    }

    #[test]
    #[should_panic]
    fn test_unsupported_length() {
        let mut hkdf = Hkdf::new("SHA-256", &[], &[]);
        hkdf.derive(&[], 90000);
    }
}
