use bake_kdf::{bake_kdf, belt_keyexpand, belt_keyrep};
use hex_literal::hex;

#[test]
fn test_keyexpand() {
    let k: [u32; 6] = [
        0xE9DEE72C, 0x8F0C0FA6, 0x2DDB49F4, 0x6F739647, 0x06075316, 0xED247A37,
    ];

    let k1 = belt_keyexpand(&k[..4]).unwrap();
    let k2 = belt_keyexpand(&k).unwrap();

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
    let mut x: [u32; 8] =
        [
            0xE9DEE72C, 0x8F0C0FA6, 0x2DDB49F4, 0x6F739647, 0x06075316, 0xED247A37, 0x39CBA383,
            0x03A98BF6,
        ];
    let d: [u32; 3] = [0x01000000, 0x00000000, 0x00000000];
    let i: [u32; 4] = [0x5BE3D612, 0x17B96181, 0xFE6786AD, 0x716B890B];

    x.iter_mut().for_each(|x| *x = u32::swap_bytes(*x));

    let out: &mut [u32] = &mut [0; 4];
    belt_keyrep::<128>(&x, &d, &i, out).unwrap();
    assert_eq!(out, [0x6BBBC233, 0x6670D31A, 0xB83DAA90, 0xD52C0541]);

    let out: &mut [u32] = &mut [0; 6];
    belt_keyrep::<192>(&x, &d, &i, out).unwrap();
    assert_eq!(
        out,
        [0x9A2532A1, 0x8CBAF145, 0x398D5A95, 0xFEEA6C82, 0x5B9C1971, 0x56A00275]
    );

    let out: &mut [u32] = &mut [0; 8];
    belt_keyrep::<256>(&x, &d, &i, out).unwrap();
    assert_eq!(
        out,
        [
            0x76E166E6, 0xAB21256B, 0x6739397B, 0x672B8796, 0x14B81CF0, 0x5955FC3A, 0xB09343A7,
            0x45C48F77
        ]
    );
}

#[test]
fn test_kdf() {
    let secret = hex!("723356E335ED70620FFB1842752092C32603EB666040920587D800575BECFC42");
    let iv = hex!("6B13ACBB086FB87618BCC2EF20A3FA89475654CB367E670A2441730B24B8AB31CD3D6487DC4EEB23456978186A069C71375D75C2DF198BAD1E61EEA0DBBFF737");
    let key = bake_kdf(&secret, &iv, 0).unwrap();
    assert_eq!(
        key,
        [
            0xDAC4D8F4, 0x11F9C523, 0xD28BBAAB, 0x32A5270E, 0x4DFA1F0F, 0x757EF8E0, 0xF30AF08F,
            0xBDE1E7F4
        ]
    );

    let key = bake_kdf(&secret, &iv, 1).unwrap();
    assert_eq!(
        key,
        [
            0x54AC0582, 0x84D679CF, 0x4C47D3D7, 0x2651F3E4, 0xEF0D61D1, 0xD0ED5BAF, 0x8FF30B89,
            0x24E599D8
        ]
    );
}
