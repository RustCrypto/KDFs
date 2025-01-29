mod parser;

struct FeedbackModeTestData {
    iv: &'static [u8],
    kin: &'static [u8],
    label: &'static [u8],
    context: &'static [u8],
    kout: &'static [u8],
}

type HmacSha1 = hmac::Hmac<sha1::Sha1>;
type HmacSha224 = hmac::Hmac<sha2::Sha224>;
type HmacSha256 = hmac::Hmac<sha2::Sha256>;
type HmacSha384 = hmac::Hmac<sha2::Sha384>;
type HmacSha512 = hmac::Hmac<sha2::Sha512>;

type CmacAes128 = cmac::Cmac<aes::Aes128>;
type CmacAes192 = cmac::Cmac<aes::Aes192>;
type CmacAes256 = cmac::Cmac<aes::Aes256>;

macro_rules! mock_output {
    ($name:ident, $size:ident) => {
        struct $name;

        impl digest::crypto_common::KeySizeUser for $name {
            type KeySize = digest::consts::$size;
        }
    };
}

mock_output!(MockOutputU128, U16);
mock_output!(MockOutputU160, U20);
mock_output!(MockOutputU256, U32);
mock_output!(MockOutputU320, U40);
mock_output!(MockOutputU480, U60);
mock_output!(MockOutputU512, U64);
mock_output!(MockOutputU528, U66);
mock_output!(MockOutputU560, U70);
mock_output!(MockOutputU1024, U128);
mock_output!(MockOutputU1040, U130);
mock_output!(MockOutputU1600, U200);
mock_output!(MockOutputU2048, U256);
mock_output!(MockOutputU2064, U258);
mock_output!(MockOutputU2400, U300);
