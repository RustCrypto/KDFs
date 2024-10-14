//! Tests for ansi-x963-kdf
//!
//! Test vectors have been generated using the java-based Bouncy-Castle
//! KDF2 implementation [KDF2BytesGenerator][1]
//!
//! [1]: https://downloads.bouncycastle.org/java/docs/bcprov-jdk18on-javadoc/
use digest::{Digest, FixedOutputReset};
use hex_literal::hex;
use sha2::{Sha224, Sha256, Sha512};

struct Fixture<'a> {
    secret: &'a [u8],
    shared_info: &'a [u8],
    expected_key: &'a [u8],
}

fn test_key_derivation<D>(fixtures: &[Fixture])
where
    D: Digest + FixedOutputReset,
{
    for Fixture {
        secret,
        shared_info,
        expected_key,
    } in fixtures.iter()
    {
        for key_length in 1..expected_key.len() {
            let mut key = vec![0u8; key_length];
            assert!(ansi_x963_kdf::derive_key_into::<D>(secret, shared_info, &mut key).is_ok());
            assert_eq!(&expected_key[..key_length], &key);
        }
    }
}

#[test]
fn test_input_output_sha224() {
    let fixtures = [
        Fixture {
            secret: &hex!("00"),
            shared_info: &[],
            expected_key: &hex!(
                "4a6ebc83b8e2b19eea640500be6bcffdddaa07b8b2f81f2c533940e4e6ad6cfd
                 e680e5ba8eb25351402f0e75a6246cf006f6dd2187185af41d04abb648124e27
                 827cf4f2b871f9bc3fb2313c4f146b44faf3be170f2d87296c9b533c516b9a48
                 dc73f73bafcc610bce18965566e3d0ca0f083c8a6a20b3b84457486e204a1014"
            ),
        },
        Fixture {
            secret: &hex!("00"),
            shared_info: &hex!("00"),
            expected_key: &hex!(
                "4bfb11552c4bf91bce4833aa06f854ceb8a3f7e435f42907e6d86e7597b20789
                 aba17dccaf09d3e26bc3dd0ad6051f0e46b830cc57091bd0ba1da24a4ab96492
                 3b47b4b73ccb6cec6aa1e6339f4fa93995baef4a3ace3cadcf1ee63eaecb868f
                 2f8ca06def29797d33673803a185574dec0c4bc0a5d0d0ffb4c527eb738d5bd2
                 4fcc424f46785f693f60ea2f00d3ff38f9f1e73847a50bf6ece7bda4abe3767f
                 19f0a767f2ea69ed84f4f5837084edd2945c39d4b459b38fc2e83264ba47896a
                 a3e106058f1d13f2b1422c7ff33c279dfc7a42cc4f775babcae8122a4dbdf427
                 a8634e9464607fe4a6f91fc59f07ab42f18dac313384b50d572cdff0b406cff2"
            ),
        },
        Fixture {
            secret: &hex!("ba5eba11bedabb1ebe5077edb0a710adb01dfacecab005eca11ab1eca55e77e011"),
            shared_info: &hex!("f005ba1100ddba11"),
            expected_key: &hex!(
                "20328557e258ecbe845fcde1002aa36dba5e29383d1b9813c2410819c09bd7d7
                 5b75f4d2ca71354080b64b3e8e3ef457f22517b074cbbbbf11d660b7b4706de1
                 5678893c6712e104b34fb776a90341c905a028bf1892aa4487899ef4436f4ac6
                 d436db25763c7fa7d43fbedac386aa69f5b156d4a84ede0b4371d34eb083fce1
                 6cb6e051e846a923a82707925838371797b09fc94134d33b48e0ab9175fdbd90
                 cd57b1570d55f5d4a391f5c15660757c447e0480bd6b6f0ca80a4e3ab5c40220
                 7d1edcc2210eb77aff4eda6e35afce2815d82ab242574b7b9d0e72d8daa1c853
                 e0b3dad4cb384ce70c5a23afd4f1e35a01fdd14f78812a5a99a93f4d57877901"
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
            shared_info: &[],
            expected_key: &hex!(
                "15f2f1a4339f5f2a313b95015cad8124d054a171ac2f31cf529dda7cfb6a38b4
                 89eefc18fa4b815bd1aded2f24eb28885993aa00b6d0171bf5005f9d39aaea10
                 016a682d1df4f869b32c48b0a9b442a1493949fb85d951d121c1143bd3d5c1af
                 b59024333110b3108625f25447665c1ebf10c6a6bbe9f018c421f4b0dcb5a993
                 42a5578600f1b0902c599a39268c12bdb1e820fd9a82212db588a71ae74cb6e4
                 1f8a792ae7c5800a0b0e3aea6ed808bedca2b0a3cc8f7b22c5effbd545f632c2
                 043a0631871a3f67ac03c5f8406b69a0dc14bd5b23e55f27a5d4462b0f0a2d23
                 18519afd330d3447bb196dd75ea7a7998db6f2fcb2a5dc134f35690a2dbcc072"
            ),
        },
        Fixture {
            secret: &hex!("00"),
            shared_info: &hex!("00"),
            expected_key: &hex!(
                "588611f65741c171a3d92c1d5343f5dd67f4fc472fc56f01c9bc568f5ac2a623
                 55af2e3db27cf364b9465ea89a489710da6c78ecc59ddf3ac6203261a6649d9e
                 45673cfcd9849e761a24b07d99f5c35167c343244c160b973b55a29408d9d988
                 654670625fbd22634494df9f4f9a5328352eb92b4104612eef6dff382c119064
                 785b35d50e5df9eee4bb06e5b102b1088d149500e934c04eac6936a09e4b36d1
                 1e4f69ae41148ec0d7b5cca9bde9db8b850660e759c75f32154bb60357145ed3
                 c0112a61a92f4eacd699c70a603df40f38babf6420587478c05ec70670e7221e
                 ce2081d38382369c0d2ec51f89db2e29146d555c7c2aa62518962824682553a7"
            ),
        },
        Fixture {
            secret: &hex!("ba5eba11bedabb1ebe5077edb0a710adb01dfacecab005eca11ab1eca55e77e011"),
            shared_info: &hex!("f005ba1100ddba11"),
            expected_key: &hex!(
                "41bf219e0dedf77305f1f79739fd917b3311e61dd504150d6f3c40195837c75a
                 441fd05332d739a43fd70e11e4be66683eb05586c6c03bbf6d8030990e724a38
                 c2ab1f5c22b0f47a84a2699d11701c6bfb3337e606130522f4f7a26df3b1cb95
                 28ca56781af9af361e7c2ac64d50f73d275d5a6c83fc67b2e05f20ab9b595cce
                 b8f205c57993647bf64c6f4ad8899eb5d0111efed1859006ec256b2e8cbb058b
                 b83a8d40fa7f435037acd155b27a87716fdd7619b900f051a2437539f830789b
                 f71080ff642285a01ff2db3e11ca5377c389be3f3851611cc8189728496fddca
                 cac6b89565fd78a1b8d4c8d407ff45e39610526668abacabede347d5c1e9fb69"
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
            shared_info: &[],
            expected_key: &hex!(
                "b8eef223e484fe7a872e4db84711a01db365b205e477c3e3170f26623e2fa230
                 4d93f6c04337d0ea7454d1f2073f8eb8ee58b361438b61f363eb1037a77f716c
                 e89b92de1146cf3831eff44361d872f61dea1f05b3e08a9330c302949f6c93bd
                 3e908f5ce5444e45a47bc0625600fff575472f04bcecc393387c244a93fbd4f4
                 26b22edbdaa5eef8565feb1d6a3c46dedb89c00efcaf3f5d95d53f936b570efb
                 18db044083a075f3d1322378a07f00694e4e21a535d91e893cacac87d877b2ab
                 da0cff964fd1c291b759c38657bc7904be9f98cc8794099a6351b68f382e2df8
                 79cab5d5a1d7f5e9d6461f015b11c47fb14cf99e496905fa95e8d7d5ec59a493"
            ),
        },
        Fixture {
            secret: &hex!("00"),
            shared_info: &hex!("00"),
            expected_key: &hex!(
                "74cc6e00677ea1683c3c3fbc6337101db4e2ffdd0053a8783fd4c9f5b53117db
                 9089ce3beef287cbe273a7c47ad1e88509842f9a70ff354280dc7a8e1c61214a
                 e698b4186af5628a28dad9ff4b25d0cfbceac9c9c522d496f8513338a9426991
                 2e0bbd2b2c500b303dae963b707ed4a05e9f57eb0c7de06da884669a93dbb29b
                 3d262e7c98e24f8cd68d0ea44fe9d5e4e0b033b0c3f77193cdf2163dfac30da9
                 eb39b147e2d9746dd1149ac512920d8e8316577e6713498beb7fa838a80b1736
                 383001d5151582a16bcf9fcc38edbafaf18ab976e01a0244b462c6b6f907ba14
                 32d14e641961c3d48e300ec5561424c4b8125cf172d06f9368bfdec0d5c57b8b"
            ),
        },
        Fixture {
            secret: &hex!("ba5eba11bedabb1ebe5077edb0a710adb01dfacecab005eca11ab1eca55e77e011"),
            shared_info: &hex!("f005ba1100ddba11"),
            expected_key: &hex!(
                "ae21b84e638fc7de4d838d2a7232655c39d2794116f00e43891170c0a16df11c
                 15afbdb903c5722e22afc885c0f851c2ccacc2a0802437bc5bef6c18a0573246
                 65de72200dac5321ed92f530ed441bc194c402055419d73f52165a2bf9985fab
                 756abce8e3b9c5e4a3d179b2eceaa6ef7b335245f480ed32a7f847921ab5e3c1
                 a8867aff9802e6f8cec4d6a5fdf3cc0c2c1a14f08ec4df3654f2579164c6ed90
                 a2262a8d492a0aa0942838952dc89f494018da5dd16c0b18ca6a9837685489bf
                 a55debb243045e83a730e5e08917836181693cb4ab1827e968e3bb0e8e3b9a0e
                 7cdab180f59168211dad86eb88fc3b4bc1dbeb0c8a8c967c5e0d1b2a84bf215c"
            ),
        },
    ];

    test_key_derivation::<Sha512>(&fixtures);
}

#[test]
fn test_errors() {
    // secret has zero length.
    assert_eq!(
        ansi_x963_kdf::derive_key_into::<Sha512>(&[], &[], &mut [0u8; 42]),
        Err(ansi_x963_kdf::Error::NoSecret)
    );

    // key has zero length.
    assert_eq!(
        ansi_x963_kdf::derive_key_into::<Sha512>(&[0u8; 42], &[], &mut [0u8; 0]),
        Err(ansi_x963_kdf::Error::NoOutput)
    );

    // shared_info has a length that causes input overflow.
    #[cfg(target_pointer_width = "64")]
    {
        // Secret
        let secret = [0u8; 42];

        // Calculate the required length for shared_info to cause an input overflow: |Z| + |SharedInfo| + 4 >= hashmaxlen
        let shared_info_len = Sha224::output_size() * (u32::MAX as usize) - secret.len() - 4;

        // Create a layout for allocation.
        let layout = std::alloc::Layout::from_size_align(shared_info_len, 1).unwrap();
        unsafe {
            // We assume that OS will not allocate physical memory for this buffer
            let p = std::alloc::alloc_zeroed(layout);
            if p.is_null() {
                panic!("Failed to allocate memory");
            }

            // Wrap the allocated pointer in a struct that will deallocate it on drop.
            struct AllocGuard {
                ptr: *mut u8,
                layout: std::alloc::Layout,
            }
            impl Drop for AllocGuard {
                fn drop(&mut self) {
                    unsafe {
                        std::alloc::dealloc(self.ptr, self.layout);
                    }
                }
            }
            let _guard = AllocGuard { ptr: p, layout };

            // Create a slice from the allocated memory.
            let shared_info = std::slice::from_raw_parts(p, shared_info_len);
            assert_eq!(
                ansi_x963_kdf::derive_key_into::<Sha224>(&secret, shared_info, &mut [0u8; 42]),
                Err(ansi_x963_kdf::Error::InputOverflow)
            );
        }
    }

    // key has a length that causes counter overflow.
    #[cfg(target_pointer_width = "64")]
    {
        let size = Sha224::output_size() * u32::MAX as usize;
        let layout = std::alloc::Layout::from_size_align(size, 1).unwrap();
        unsafe {
            // We assume that OS will not allocate physicall memory for this buffer
            let p = std::alloc::alloc_zeroed(layout);
            let buf = std::slice::from_raw_parts_mut(p, size);
            assert_eq!(
                ansi_x963_kdf::derive_key_into::<Sha224>(&[0u8; 42], &[], buf),
                Err(ansi_x963_kdf::Error::CounterOverflow)
            );
            std::alloc::dealloc(p, layout)
        };
    }
}
