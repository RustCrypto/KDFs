use digest::{Digest, FixedOutputReset};
use hex_literal::hex;
use sha2::{Sha224, Sha256, Sha512};

struct Fixture<'a> {
    secret: &'a [u8],
    other_info: &'a [u8],
    expected_key: &'a [u8],
}

fn test_key_derivation<D>(fixtures: &[Fixture])
where
    D: Digest + FixedOutputReset,
{
    for f in fixtures.iter() {
        let mut buf = [0u8; 256];
        for key_length in 1..f.expected_key.len() {
            let key = &mut buf[..key_length];
            concat_kdf::derive_key_into::<D>(f.secret, f.other_info, key).unwrap();
            assert_eq!(&f.expected_key[..key_length], key);
        }
    }
}

#[test]
fn test_input_output_sha224() {
    let fixtures = [
        Fixture {
            secret: &hex!("00"),
            other_info: &[],
            expected_key: &hex!(
                "5a5f55dc7112b236b7b9e4734bfa2276a565c802b0e704e84d6f3afc19364a9b"
                "a2e6fdfe0d05c792b6ccc1c694efc1d253cc44975d5f7a1dac05745422639850"
                "0679a1a65f0586d655ed6e5d62a46d05741ae7133edc866f863fdeeb3b181a5b"
                "b7539309b809fba02c5f036926bcb25cb966683664634de66f4d72b3f1d671c0"
                "acb28bf4618c5faecc07ecb4bb60cdba51d3c902637fecb0173ab8185bc2939f"
                "d66d35a76ac3644e79166c4445123dfb91aa787e76b91b917e74eefb211a1264"
                "f0b493a980533252be954681094081628ad7ec9d8c77f3b05254b326e45cfeb2"
                "3b5dd5697ae7fe11e44af84c5254ae6d32e8079c442e19a4e0bdad348a8c7d73"
            ),
        },
        Fixture {
            secret: &hex!("00"),
            other_info: &hex!("00"),
            expected_key: &hex!(
                "8741be040b4a815d358adf598bdabac4293a7e1353967aedbb80bcebfbd11dc0"
                "7c520882f90500ac6d9fe6a078e3213d056e9ca7ed7535f11a6417a843a56465"
                "cf7d67775d3392758d71c233c6611e45a96e2bfdb81ea1d3ccdfed90b768b1b1"
                "c3518e4c30cf9224af2a55e68f35b496a1239148732ec15e2419b1da97ace8c9"
                "fb7de3fe03656b7978a5286a1a0e212a65c9fb9b5c8d33cc1995497903492a27"
                "3e5be119898695e1872a43f2d32f95ac688816b3d4b344645d525f49859e8a70"
                "9d03d0d7ac947057f3eb5c3a830c510db96856fa7206d8a0f784223acf9cd211"
                "4d4a9d38c463ebede8ae758d577bf5704d30c5b0bcd225c007c8092bbaa26909"
            ),
        },
        Fixture {
            secret: &hex!("ba5eba11bedabb1ebe5077edb0a710adb01dfacecab005eca11ab1eca55e77e011"),
            other_info: &hex!("f005ba1100ddba11"),
            expected_key: &hex!(
                "3467360b50fee27cfb8e6bdc28ef5252ac0938a2987693a23478bcdbe43a0fe6"
                "d2de581e4858c544722caf6776d423da3b73b623b4e39dcdd6d2b51685399e99"
                "1d53c53afd44cd294b992dccfb37a9cdaf9dee05bd2053fa9f1e0e3b3719e3c4"
                "3b0c7ad2aefb0bfb9b69e32c61bf3690d60c74cd7e37b0bf043e873028828a4a"
                "a6efbd8f9aedb1ab858616fe93878c5d815b6fa7cf13a205cced53a6fd8d7685"
                "339bb4a0be0f9ccb68419b1e0814acfcf67d2d06a492d429d2e8740ecbd94ceb"
                "cef9696bbf26867a7b192780deb59c7ae7ed97844a359a790a00aaa79f6aadae"
                "8bfc62ab653a8375de876cb5865e8a60d92b403be34050ac74e5da99787b3357"
            ),
        },
    ];

    test_key_derivation::<Sha224>(&fixtures);
}

#[test]
fn test_input_output_sha256() {
    let fixtures = [
        Fixture {
            secret: &hex!("00"),
            other_info: &[],
            expected_key: &hex!(
                "060dc63e5595dffbd161c9ec98bc06fcf67cb22e2e75ecdf0003821388aeee4d"
                "182cf10a4a3cc9c7ed07a46bfc0327a406e14b2e892b62471a523ceea8cb7664"
                "598cd1428ca03f178cc23c367994cd739eb3e029f63b3e7079e4df62717f2dd0"
                "d110457e8900a7bff0e9474ecd94fb6cd001d6928d7e018132678ac22013bdd0"
                "5f8b7ad1b5241a8326638b7f596fcc965cc2c81665ad275d0110a9af8fe1d8fb"
                "69af0678d2e4cd5b3a9dfeee6343496ee4ec37b3d4240954b64364acb9aa47f8"
                "49befd6c253f0eb97f3fb0c118542c39519746da27b55f32cca541f9a1a16091"
                "6a8814853bd214d9f0faf8d19724d53383fd0084a9471f67b989d47e225aa1a8"
            ),
        },
        Fixture {
            secret: &hex!("00"),
            other_info: &hex!("00"),
            expected_key: &hex!(
                "10487d86ce3584e156874ed9b2650e8d772a8d1fdbb1c9111bf7e2fbcab18ccb"
                "e44728408fa247053c017f791d5d2fe87752119c5010006ffc4e098efbaea679"
                "52a554d18aa44185bbd82ea8882354ddc5286b9fd1af206bb9c88dbf424e4b1b"
                "5f54b6ff037cd93f528964739d54d41a837e86c0baa777865a2a48bb15c910a9"
                "4e01ccc1186d19c2db4e65bd81dd29c492d88668f6fc70c5fa20855ed535d20e"
                "5acee3f2b6a0568f4d1048d1ca04e85606e14d0bc48ebb7cf063a780f0096129"
                "52da97e695e38843ae3fcc649f301915fc8e7675d0065aabb2c6698daaf494a4"
                "df6d80b66a8b32c5bdd8ecdb650ae4fc2b47e6f50711eedd42dcbf2864e089cd"
            ),
        },
        Fixture {
            secret: &hex!("ba5eba11bedabb1ebe5077edb0a710adb01dfacecab005eca11ab1eca55e77e011"),
            other_info: &hex!("f005ba1100ddba11"),
            expected_key: &hex!(
                "a400be9935d0c843a1504aa64f6078195b6e20ea3fe64bb8d7f29aaea6a351bf"
                "7e40cafe54e86c4d502f82a390ab77098e8cccf905b5826d475e8316583eb53f"
                "fc6afda60479492c5142db5896cbd0438e583d64162e448e68a3725944866f3e"
                "55ea6d4e3eea479b7d0a5c7a78d4425bc3c118a564f078f6dc41439c255e87c9"
                "be4e3e4a80509f84727ee661b9f04a8da4ece7214328f5180e96a9d641136ae7"
                "e2c83707106623dd890cc0c8a04a4af628b530da938753e07c4891204014b675"
                "1beb080ee8c3391607652411423567b60a56ca9efe5bc858c9a23f87b13cffa6"
                "bcaf5fab9ad33ff2a284c15c8af0195674b46be2f98fad136eb327a8a60a8f4e"
            ),
        },
    ];

    test_key_derivation::<Sha256>(&fixtures);
}

#[test]
fn test_input_output_sha512() {
    let fixtures = [
        Fixture {
            secret: &hex!("00"),
            other_info: &[],
            expected_key: &hex!(
                "63e1c62226df5825c32eceb32e9f318316f54d8b56a12f764c88ec4f4b4ed80c
                 b4fd20c2b9fd522a9439f067dfabc8cc2da781dd7b0abc0821909dff25ff33db
                 bac4619b1569765a23fd8fb91fbad73903d48a1088ae1b710437f2fc08815625
                 31248ae2f6c12a7156eb27e881ed186f4de45cf22a97cca0d67a8dc5dc7acf8c
                 6dc447966ff13da6f4d347c7421208f8553a9aeda6f66bcbfc556f47a402f20e
                 b6f1a0c21bd375fa2246f7faad19a05c22536770ffb3466e544b0723005cea89
                 40706c1e16e81000d2829e7ab2e1a13f278396da38bd17414cf14d5dfe33212f
                 c2ca53bb60df0e36fc76d4861e540da48db328b56e9bf5561a30ecc15184e70b"
            ),
        },
        Fixture {
            secret: &hex!("00"),
            other_info: &hex!("00"),
            expected_key: &hex!(
                "5a91d2ac619076c5eb6aae55512841d76b6442f98e23372660e854dc5b327844
                 77e504f2fd620c9328711b682b8a21a0173cfd0c42a96263006e992d8483193f
                 03347c4cd479f8d0797fe6613fa999cd40bac7fad61715210c044dc722e8db8c
                 8b4a35076d17b0eb6170429ba2fb51371ddfc6189cb90dc27ae701523a709f67
                 08c5d1d4140e1434aeb8b593e41f21616543c7727dffe14f4c424dd487d01a92
                 1370993c359c2a45c9a6584df5a09e36c14453df46a9f9fa8b65ebd790eec122
                 a0789cabb04854e392656eade6e40d821826708ba1fb078fd1d15565902c68c5
                 531c0be6415f9b24721fdc118fafaef6f1b5db03d895e7ff503ddbd73d111f38"
            ),
        },
        Fixture {
            secret: &hex!("ba5eba11bedabb1ebe5077edb0a710adb01dfacecab005eca11ab1eca55e77e011"),
            other_info: &hex!("f005ba1100ddba11"),
            expected_key: &hex!(
                "247e5d73b8f45ff573294437d6e4fddecf95dee5f54b9ad8db11aa3f856e02b2
                 5da6159680c87f629c0ef6fbad79ef6499561d444106a765a7c7a96055ee684e
                 37e406b52ca3c6ca6690b5b93f8b1a5609a4b159a90a8ce9391f6e2738447034
                 8c2dc71f559cd2a9f471063a056ab138634679587dd51ac6d4729b7f94b44343
                 00dee4eb7c43c11919f83ee52aa11150c38476b8e675e3d2a20dac03b7153d05
                 92041e8324b7509f64a098060e74eb7d51ccfd9231154ef0fc0ee9de46252794
                 9f149b14636338fb9fef85c56f8a5d6f95e9268ed312053abe7cb5f8e6e405a4
                 058d5ef840e5ec6218ec2dfc4acdff1bea1a5341b9ea47e61642c7214b305083"
            ),
        },
    ];

    test_key_derivation::<Sha512>(&fixtures);
}

#[test]
fn test_no_secret() {
    assert_eq!(
        concat_kdf::derive_key_into::<Sha512>(&[], &[], &mut [0u8; 42]),
        Err(concat_kdf::Error::NoSecret)
    );
}

#[test]
fn test_no_output() {
    assert_eq!(
        concat_kdf::derive_key_into::<Sha512>(&[0u8; 42], &[], &mut [0u8; 0]),
        Err(concat_kdf::Error::NoOutput)
    );
}
