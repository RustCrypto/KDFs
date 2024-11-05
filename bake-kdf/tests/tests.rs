use bake_kdf::{bake_kdf, belt_keyexpand, belt_keyrep};
use hex_literal::hex;

#[test]
fn test_keyexpand() {
    let k_u32: [u32; 6] = [
        0xE9DEE72C, 0x8F0C0FA6, 0x2DDB49F4, 0x6F739647, 0x06075316, 0xED247A37,
    ];
    let mut k = [0u8; 24];
    for (src, dst) in k_u32.iter().zip(k.chunks_exact_mut(4)) {
        dst.copy_from_slice(&src.to_le_bytes());
    }

    let k1 = belt_keyexpand::<16>(&k[..16].try_into().unwrap());
    let k2 = belt_keyexpand(&k);

    assert_eq!(
        k1,
        [
            0xE9DEE72C, 0x8F0C0FA6, 0x2DDB49F4, 0x6F739647, 0xE9DEE72C, 0x8F0C0FA6, 0x2DDB49F4,
            0x6F739647
        ]
    );
    assert_eq!(
        k2,
        [
            0xE9DEE72C, 0x8F0C0FA6, 0x2DDB49F4, 0x6F739647, 0x06075316, 0xED247A37, 0x4B09A17E,
            0x8450BF66
        ]
    );
}

#[test]
fn test_keyrep() {
    let x: [u8; 32] =
        hex!("E9DEE72C 8F0C0FA6 2DDB49F4 6F739647 06075316 ED247A37 39CBA383 03A98BF6");
    let d: [u8; 12] = hex!("01000000 00000000 00000000");
    let i: [u8; 16] = hex!("5BE3D612 17B96181 FE6786AD 716B890B");

    let out: [u8; 16] = belt_keyrep(&x, &d, &i);
    assert_eq!(out, hex!("6BBBC233 6670D31A B83DAA90 D52C0541"));

    let out: [u8; 24] = belt_keyrep(&x, &d, &i);
    assert_eq!(
        out,
        hex!("9A2532A1 8CBAF145 398D5A95 FEEA6C82 5B9C1971 56A00275"),
    );

    let out: [u8; 32] = belt_keyrep(&x, &d, &i);
    assert_eq!(
        out,
        hex!("76E166E6 AB21256B 6739397B 672B8796 14B81CF0 5955FC3A B09343A7 45C48F77"),
    );
}

#[test]
fn test_kdf() {
    let secret = hex!("723356E3 35ED7062 0FFB1842 752092C3 2603EB66 60409205 87D80057 5BECFC42");
    let iv = hex!(
        "6B13ACBB 086FB876 18BCC2EF 20A3FA89 475654CB 367E670A 2441730B 24B8AB31"
        "CD3D6487 DC4EEB23 45697818 6A069C71 375D75C2 DF198BAD 1E61EEA0 DBBFF737"
    );
    let key = bake_kdf(&secret, &iv, 0);
    assert_eq!(
        key,
        hex!("DAC4D8F4 11F9C523 D28BBAAB 32A5270E 4DFA1F0F 757EF8E0 F30AF08F BDE1E7F4"),
    );

    let key = bake_kdf(&secret, &iv, 1);
    assert_eq!(
        key,
        hex!("54AC0582 84D679CF 4C47D3D7 2651F3E4 EF0D61D1 D0ED5BAF 8FF30B89 24E599D8"),
    );
}
