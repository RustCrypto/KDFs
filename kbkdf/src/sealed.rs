use digest::{
    consts::{U16, U24, U32, U8},
    generic_array::typenum::Unsigned,
};

mod private {
    use digest::consts::{U16, U24, U32, U8};

    pub trait Sealed {}

    impl Sealed for U8 {}
    impl Sealed for U16 {}
    impl Sealed for U24 {}
    impl Sealed for U32 {}
}

/// Marker used to register valid values for R in the KBKDF
pub trait R: Unsigned + private::Sealed {}

impl R for U8 {}
impl R for U16 {}
impl R for U24 {}
impl R for U32 {}
