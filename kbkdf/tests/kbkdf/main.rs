#[macro_use]
mod macros;

mod counter_mode;

struct CounterModeTestData {
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

type CmacAes128 = cmac::Cmac::<aes::Aes128>;
type CmacAes192 = cmac::Cmac::<aes::Aes192>;
type CmacAes256 = cmac::Cmac::<aes::Aes256>;

struct MockOutputU128;

impl digest::crypto_common::KeySizeUser for MockOutputU128 {
    type KeySize = digest::consts::U16;
}

struct MockOutputU160;

impl digest::crypto_common::KeySizeUser for MockOutputU160 {
    type KeySize = digest::consts::U20;
}

struct MockOutputU320;

impl digest::crypto_common::KeySizeUser for MockOutputU320 {
    type KeySize = digest::consts::U40;
}

struct MockOutputU256;

impl digest::crypto_common::KeySizeUser for MockOutputU256 {
    type KeySize = digest::consts::U32;
}
