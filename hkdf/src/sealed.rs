use hmac::digest::{
    Digest, FixedOutput, KeyInit, Output, Update,
    core_api::{BlockSizeUser, CoreWrapper, OutputSizeUser},
};
use hmac::{EagerHash, Hmac, HmacCore, SimpleHmac};

pub trait Sealed<H: OutputSizeUser> {
    type Core: Clone;

    fn new_from_slice(key: &[u8]) -> Self;

    fn new_core(key: &[u8]) -> Self::Core;

    fn from_core(core: &Self::Core) -> Self;

    fn update(&mut self, data: &[u8]);

    fn finalize(self) -> Output<H>;
}

impl<H> Sealed<H> for Hmac<H>
where
    H: EagerHash + OutputSizeUser,
{
    type Core = HmacCore<H>;

    #[inline(always)]
    fn new_from_slice(key: &[u8]) -> Self {
        KeyInit::new_from_slice(key).expect("HMAC can take a key of any size")
    }

    #[inline(always)]
    fn new_core(key: &[u8]) -> Self::Core {
        HmacCore::new_from_slice(key).expect("HMAC can take a key of any size")
    }

    #[inline(always)]
    fn from_core(core: &Self::Core) -> Self {
        CoreWrapper::from_core(core.clone())
    }

    #[inline(always)]
    fn update(&mut self, data: &[u8]) {
        Update::update(self, data);
    }

    #[inline(always)]
    #[allow(deprecated)] // clone_from_slice
    fn finalize(self) -> Output<H> {
        // Output<H> and Output<H::Core> are always equal to each other,
        // but we can not prove it at type level
        Output::<H>::clone_from_slice(&self.finalize_fixed())
    }
}

impl<H: Digest + BlockSizeUser + Clone> Sealed<H> for SimpleHmac<H> {
    type Core = Self;

    #[inline(always)]
    fn new_from_slice(key: &[u8]) -> Self {
        KeyInit::new_from_slice(key).expect("HMAC can take a key of any size")
    }

    #[inline(always)]
    fn new_core(key: &[u8]) -> Self::Core {
        KeyInit::new_from_slice(key).expect("HMAC can take a key of any size")
    }

    #[inline(always)]
    fn from_core(core: &Self::Core) -> Self {
        core.clone()
    }

    #[inline(always)]
    fn update(&mut self, data: &[u8]) {
        Update::update(self, data);
    }

    #[inline(always)]
    #[allow(deprecated)] // clone_from_slice
    fn finalize(self) -> Output<H> {
        // Output<H> and Output<H::Core> are always equal to each other,
        // but we can not prove it at type level
        Output::<H>::clone_from_slice(&self.finalize_fixed())
    }
}
