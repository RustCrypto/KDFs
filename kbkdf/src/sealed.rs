use digest::{
    consts::{U16, U24, U32, U8},
    generic_array::typenum::Unsigned,
};

/// Marker used to register valid values for R in the KBKDF
pub trait R: Unsigned {}

impl R for U8 {}
impl R for U16 {}
impl R for U24 {}
impl R for U32 {}
