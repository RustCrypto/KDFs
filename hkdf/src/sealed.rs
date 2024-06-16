use hmac::digest::{
    block_buffer::{BufferKind, Eager, Lazy},
    core_api::{BlockSizeUser, BufferKindUser, CoreWrapper, OutputSizeUser},
    Digest, FixedOutput, KeyInit, Update,
};
use hmac::{EagerHash, Hmac, HmacCore, SimpleHmac};

static EXPECT_MSG: &str = "HMAC can take a key of any size";

pub trait Sealed: OutputSizeUser + Sized {
    type FullHmac: KeyInit + Update + FixedOutput;
    type CoreHmac: KeyInit;

    fn core_to_full(core: &Self::CoreHmac) -> Self::FullHmac;

    fn new_core(key: &[u8]) -> Self::CoreHmac {
        Self::CoreHmac::new_from_slice(key).expect(EXPECT_MSG)
    }

    fn new_full(key: &[u8]) -> Self::FullHmac {
        Self::FullHmac::new_from_slice(key).expect(EXPECT_MSG)
    }
}

impl<C, K> Sealed for CoreWrapper<C>
where
    K: HmacKind<Self> + BufferKind,
    C: BufferKindUser<BufferKind = K> + OutputSizeUser,
{
    type FullHmac = K::FullHmac;
    type CoreHmac = K::CoreHmac;

    fn core_to_full(core: &Self::CoreHmac) -> Self::FullHmac {
        K::core_to_full(core)
    }
}

pub trait HmacKind<H> {
    type FullHmac: OutputSizeUser + KeyInit + Update + FixedOutput;
    type CoreHmac: KeyInit;

    fn core_to_full(core: &Self::CoreHmac) -> Self::FullHmac;
}

impl<H: EagerHash> HmacKind<H> for Eager {
    type FullHmac = Hmac<H>;
    type CoreHmac = HmacCore<H>;

    fn core_to_full(core: &Self::CoreHmac) -> Self::FullHmac {
        CoreWrapper::from_core(core.clone())
    }
}

impl<H: Digest + Clone + BlockSizeUser> HmacKind<H> for Lazy {
    type FullHmac = SimpleHmac<H>;
    type CoreHmac = SimpleHmac<H>;

    fn core_to_full(core: &Self::CoreHmac) -> Self::FullHmac {
        core.clone()
    }
}
