use super::*;

macro_rules! impl_kdf {
    ($($mode:ty),+ $(,)?) => {
        $(
            /// Derives a key using `secret` as `kin` and `non_secret` as `context`.
            ///
            /// The label is empty, and the separator, counter, and output length
            /// fields are enabled. Feedback mode preserves the configured IV.
            ///
            /// The output must be exactly `K::KeySize` bytes. Invalid output lengths,
            /// PRF key lengths, and counter overflows return [`kdf::Error`].
            impl<Prf, K, R> Kdf for $mode
            where
                Prf: Mac + KeyInit,
                K: KeySizeUser,
                K::KeySize: ArraySize + Mul<U8>,
                <K::KeySize as Mul<U8>>::Output: Unsigned,
                Prf::OutputSize: ArraySize + Mul<U8>,
                <Prf::OutputSize as Mul<U8>>::Output: Unsigned,
                R: sealed::R,
            {
                fn derive_key(
                    &self,
                    secret: &[u8],
                    non_secret: &[u8],
                    out: &mut [u8],
                ) -> kdf::Result<()> {
                    if out.len() != K::KeySize::USIZE {
                        return Err(kdf::Error);
                    }

                    // `Kbkdf::derive` assumes a valid PRF key length.
                    Prf::new_from_slice(secret).map_err(|_| kdf::Error)?;
                    let params = Params::builder(secret).with_context(non_secret).build();
                    let key = self.derive(params).map_err(|_| kdf::Error)?;
                    out.copy_from_slice(&key);
                    Ok(())
                }
            }
        )+
    };
}

impl_kdf!(
    Counter<Prf, K, R>,
    Feedback<'_, Prf, K, R>,
    DoublePipeline<Prf, K, R>,
);
