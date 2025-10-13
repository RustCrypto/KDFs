use hmac::digest::{
    Digest, FixedOutput, KeyInit, Output, Update,
    block_api::{BlockSizeUser, OutputSizeUser},
};
use hmac::{EagerHash, Hmac, SimpleHmac};

/// Trait representing a HMAC implementation.
///
/// Most users should use [`Hmac`] or [`SimpleHmac`].
pub trait HmacImpl<H: OutputSizeUser>: Clone {
    /// Create new HMAC state with the given key.
    fn new_from_slice(key: &[u8]) -> Self;

    /// Update HMAC state.
    fn update(&mut self, data: &[u8]);

    /// Finalize the HMAC state and get generated tag.
    fn finalize(self) -> Output<H>;
}

impl<H: EagerHash> HmacImpl<H> for Hmac<H> {
    #[inline(always)]
    fn new_from_slice(key: &[u8]) -> Self {
        KeyInit::new_from_slice(key).expect("HMAC can take a key of any size")
    }

    #[inline(always)]
    fn update(&mut self, data: &[u8]) {
        Update::update(self, data);
    }

    #[inline(always)]
    fn finalize(self) -> Output<H> {
        Output::<H>::try_from(&self.finalize_fixed()[..])
            .expect("Output<H> and Output<H::Core> are always equal to each other")
    }
}

impl<H> HmacImpl<H> for SimpleHmac<H>
where
    H: Digest + BlockSizeUser + Clone,
{
    #[inline(always)]
    fn new_from_slice(key: &[u8]) -> Self {
        KeyInit::new_from_slice(key).expect("HMAC can take a key of any size")
    }

    #[inline(always)]
    fn update(&mut self, data: &[u8]) {
        Update::update(self, data);
    }

    #[inline(always)]
    fn finalize(self) -> Output<H> {
        Output::<H>::try_from(&self.finalize_fixed()[..])
            .expect("Output<H> and Output<H::Core> are always equal to each other")
    }
}
