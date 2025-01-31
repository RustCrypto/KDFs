use super::{Array, Counter, DoublePipeline, Feedback, Kbkdf, Params};
use core::convert::TryFrom;
use digest::{consts::*, crypto_common::KeySizeUser};
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
            "241C3FBAABEDE87601B1C778B24F9A32"
            "742A14FE34DA61D77E8352EF9D6C7FC8"
            "E335E32344E21D7DC0CD627D7E2FF973"
            "992611F372C5D3DD91C100F2C6DB2CAF"
        ),
        expected: &hex!(
            "0FBF4313B2F1AF1F98C9763FE7F816CD"
            "6464234F7C524F0C4ACDF66F287B01EB"
            "82D3A90CEF26EE996EE4F0295FA7FA36"
            "1E2E85DC710A236974E1ABBC342F4E23"
            "D9A8F6B1ADC4C48332C5ED88C42FDCFB"
            "BA34CF70F1EA599908FBE35E2C121E0D"
            "BFD94D45C70FC9D9CCB899E439D21F88"
            "D3924EF5EC8613E5C386DE7B22427FC4"
        ),
    },
    KnownValue {
        iv: None,
        use_l: true,
        use_separator: true,
        label: &[0x22, 0x33],
        context: &[0x0, 0x11],
        key: &hex!(
            "241C3FBAABEDE87601B1C778B24F9A32"
            "742A14FE34DA61D77E8352EF9D6C7FC8"
            "E335E32344E21D7DC0CD627D7E2FF973"
            "992611F372C5D3DD91C100F2C6DB2CAF"
        ),
        expected: &hex!(
            "7F21415C8ED32102BE3C284E970B3DF4"
            "5FCE9F7464FC6616ED59AC1F1ECA0565"
            "8E2868C57974293A79D49B576C4083C3"
            "48AD07508E8A673D0F6B496ED444E0DE"
            "80AE1F146F8C2CBFE09F1D04516338DE"
            "9E5284236FE29CB2D71A183B7573DFE7"
            "0A8321ADAAF6FC2EDC73C228289948DD"
            "3230D56E7A9103E2736957B326ACE921"
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
                Params::builder(v.key)
                    .use_l(v.use_l)
                    .use_separator(v.use_separator)
                    .with_label(v.label)
                    .with_context(v.context)
                    .build()
            ),
            Ok(Array::<_, _>::try_from(v.expected).unwrap().clone()),
            "key derivation failed for (index: {i}):\n{v:x?}"
        );
    }
}

#[test]
fn test_counter_kbkdfvs() {
    type HmacSha256 = hmac::Hmac<sha2::Sha256>;
    struct MockOutput;

    impl KeySizeUser for MockOutput {
        type KeySize = U32;
    }

    let counter = Counter::<HmacSha256, MockOutput>::default();
    // KDFCTR_gen.txt count 15
    assert_eq!(
            counter.derive(Params::builder(
                &hex!("43eef6d824fd820405626ab9b6d79f1fd04e126ab8e17729e3afc7cb5af794f8")).use_l(false).use_separator(
                false).with_label(
                &hex!("5e269b5a7bdedcc3e875e2725693a257fc60011af7dcd68a3358507fe29b0659ca66951daa05a15032033650bc58a27840f8fbe9f4088b9030738f68")).build()
            ),
            Ok(Array::<u8, U32>::from(hex!("f0a339ecbcae6add1afb27da3ba40a1320c6427a58afb9dc366b219b7eb29ecf")).clone()),
        );
}

static KNOWN_VALUES_FEEDBACK_HMAC_SHA256: &[KnownValue] = &[
    KnownValue {
        iv: Some(b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
        use_l: true,
        use_separator: true,
        label: &[0x22, 0x33],
        context: &[0x0, 0x11],
        key: &hex!(
            "241C3FBAABEDE87601B1C778B24F9A32"
            "742A14FE34DA61D77E8352EF9D6C7FC8"
            "E335E32344E21D7DC0CD627D7E2FF973"
            "992611F372C5D3DD91C100F2C6DB2CAF"
        ),
        expected: &hex!(
            "C8C8E79188DB5732B52F81111E2982BD"
            "479865EF98E90A823926BC0EA1EB173B"
            "21CA03B80228A6A1E27BE64DA382F1B7"
            "ADFF97CF43598AF2435827B2F6E78DD5"
            "F9CBCC4948775451AD2BD44A9DBE2EE4"
            "6FA5A73463E10142A3A1228183B45BC8"
            "D3831AA13EED6F94E8F221FACBC80F8B"
            "D19BDF06EC82DE7AE0FE0EE37CA51FF2"
        ),
    },
    KnownValue {
        iv: None,
        use_l: true,
        use_separator: true,
        label: &[0x22, 0x33],
        context: &[0x0, 0x11],
        key: &hex!(
            "241C3FBAABEDE87601B1C778B24F9A32"
            "742A14FE34DA61D77E8352EF9D6C7FC8"
            "E335E32344E21D7DC0CD627D7E2FF973"
            "992611F372C5D3DD91C100F2C6DB2CAF"
        ),
        expected: &hex!(
            "7F21415C8ED32102BE3C284E970B3DF4"
            "5FCE9F7464FC6616ED59AC1F1ECA0565"
            "B0BDCC163BF8119490B0B82715FF3EF1"
            "B52DF9A81BC836BA6FC5168C08CE837B"
            "0CB7C18D1C47459DF6A05C16C140109E"
            "8FC15D0EC9541FC41E127EBBDBC48CDE"
            "93E8909855F9070E9B709A497D31A825"
            "3E3CB4EEB1C18586277B2F76E4BF9FF0"
        ),
    },
];

#[test]
fn test_static_values_feedback() {
    type HmacSha256 = hmac::Hmac<sha2::Sha256>;
    type HmacSha512 = hmac::Hmac<sha2::Sha512>;

    for (v, i) in KNOWN_VALUES_FEEDBACK_HMAC_SHA256.iter().zip(0..) {
        let iv = v.iv.map(|iv| Array::try_from(iv).unwrap());
        let feedback = Feedback::<HmacSha256, HmacSha512>::new(iv.as_ref());
        assert_eq!(
            feedback.derive(
                Params::builder(v.key)
                    .use_l(v.use_l)
                    .use_separator(v.use_separator)
                    .with_label(v.label)
                    .with_context(v.context)
                    .build()
            ),
            Ok(Array::<_, _>::try_from(v.expected).unwrap().clone()),
            "key derivation failed for (index: {i}):\n{v:x?}"
        );
    }
}

static KNOWN_VALUES_DOUBLE_PIPELINE_HMAC_SHA256: &[KnownValue] = &[KnownValue {
    iv: None,
    use_l: false, //true,
    use_separator: true,
    label: &hex!("921ab061920b191de12f746ac9de08"),
    context: &hex!("4f2c20f01775e27bcacdc21ee4a5ff0387758f36d8ec71c7a8c8208284f650b611837e"),
    key: &hex!("7d4f86fdfd1c4ba04c674a68d60316d12c99c1b1f44f0a8e02bd2601377ebcd9"),
    expected: &hex!(
        "506bc2ba51410b2a6e7c05d33891520d"
        "dd5f702ad3d6203d76d8dae1216d0783"
        "d8c59fae2e821d8eff2d8ddd93a6741c"
        "8f144fb96e9ca7d7c532468f213f5efe"
    ),
}];

#[test]
fn test_static_values_double_pipeline() {
    type HmacSha256 = hmac::Hmac<sha2::Sha256>;

    struct MockOutput;

    impl KeySizeUser for MockOutput {
        type KeySize = U64;
    }

    for (v, i) in KNOWN_VALUES_DOUBLE_PIPELINE_HMAC_SHA256.iter().zip(0..) {
        let dbl_pipeline = DoublePipeline::<HmacSha256, MockOutput>::default();
        assert_eq!(
            dbl_pipeline.derive(
                Params::builder(v.key)
                    .use_l(v.use_l)
                    .use_separator(v.use_separator)
                    .use_counter(false)
                    .with_label(v.label)
                    .with_context(v.context)
                    .build(),
            ),
            Ok(Array::<_, _>::try_from(v.expected).unwrap().clone()),
            "key derivation failed for (index: {i}):\n{v:x?}"
        );
    }
}
