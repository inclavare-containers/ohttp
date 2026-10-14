use ::hpke::generic_array::{
    typenum::{Unsigned, U0, U12, U16, U32},
    GenericArray,
};
use aead::{AeadCore, AeadInPlace, Error as AeadError, KeyInit, KeySizeUser};
use aws_lc_rs::aead::{
    Aad, LessSafeKey, Nonce, UnboundKey, AES_128_GCM, AES_256_GCM, CHACHA20_POLY1305,
};

use super::SymKey;
use crate::{
    crypto::{Decrypt, Encrypt},
    err::Res,
    hpke::Aead as AeadId,
};

/// All the nonces are the same length.  Exploit that.
pub const NONCE_LEN: usize = 12;
const COUNTER_LEN: usize = 8;
const TAG_LEN: usize = 16;

type SequenceNumber = u64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Encrypt,
    Decrypt,
}

/// Wrap an aws-lc `Unspecified` (whose contents are deliberately opaque)
/// as the `aead::Error` the `RustCrypto` traits expect.  The details of the
/// aws-lc error are not actionable at this layer.
fn aws_err(_e: aws_lc_rs::error::Unspecified) -> AeadError {
    AeadError
}

fn mk_nonce(n: &[u8]) -> Result<Nonce, AeadError> {
    Nonce::try_assume_unique_for_key(n).map_err(aws_err)
}

fn new_key(alg: &'static aws_lc_rs::aead::Algorithm, key: &[u8]) -> LessSafeKey {
    // Only called where the key length is compile-time fixed (engine
    // `KeySize`), so `UnboundKey::new` cannot fail.
    LessSafeKey::new(UnboundKey::new(alg, key).expect("fixed key size"))
}

/// Runtime-length variant for the standalone path: an exported key of a
/// size that does not match the algorithm is an error, not a panic.
fn try_new_key(alg: &'static aws_lc_rs::aead::Algorithm, key: &[u8]) -> Res<LessSafeKey> {
    UnboundKey::new(alg, key)
        .map(LessSafeKey::new)
        .map_err(|_| crate::err::Error::Internal)
}

/// One engine per AEAD: raw key bytes plus the algorithm constant.
///
/// `LessSafeKey` is not `Clone`, but the `rust_hpke::aead::Aead` trait
/// requires its `AeadImpl` to be; holding the key bytes and building the
/// `LessSafeKey` per call satisfies the bound at the cost of one
/// `EVP_AEAD_CTX` init per chunk.  The clone path itself (the trait bound
/// user) never fires on the production hot path: an HPKE context creates
/// its engine once via `KeyInit::new` and only the context's
/// `cfg(test)`-only `Clone` impl would clone the engine.
macro_rules! impl_engine {
    ($name:ident, $alg:expr, $keysize:ty) => {
        #[derive(Clone)]
        pub struct $name {
            key: [u8; <$keysize as Unsigned>::USIZE],
        }

        impl KeySizeUser for $name {
            type KeySize = $keysize;
        }

        impl KeyInit for $name {
            fn new(key: &GenericArray<u8, Self::KeySize>) -> Self {
                let mut k = [0u8; <$keysize as Unsigned>::USIZE];
                k.copy_from_slice(key.as_slice());
                Self { key: k }
            }
        }

        impl Drop for $name {
            fn drop(&mut self) {
                zeroize::Zeroize::zeroize(&mut self.key);
            }
        }

        impl AeadCore for $name {
            type NonceSize = U12;
            type TagSize = U16;
            type CiphertextOverhead = U0;
        }

        impl AeadInPlace for $name {
            fn encrypt_in_place_detached(
                &self,
                n: &GenericArray<u8, Self::NonceSize>,
                aad: &[u8],
                buffer: &mut [u8],
            ) -> Result<GenericArray<u8, Self::TagSize>, AeadError> {
                let key = new_key($alg, &self.key);
                let tag = key
                    .seal_in_place_separate_tag(mk_nonce(n.as_slice())?, Aad::from(aad), buffer)
                    .map_err(aws_err)?;
                Ok(GenericArray::clone_from_slice(tag.as_ref()))
            }

            fn decrypt_in_place_detached(
                &self,
                n: &GenericArray<u8, Self::NonceSize>,
                aad: &[u8],
                buffer: &mut [u8],
                tag: &GenericArray<u8, Self::TagSize>,
            ) -> Result<(), AeadError> {
                let key = new_key($alg, &self.key);
                key.open_in_place_separate_tag(
                    mk_nonce(n.as_slice())?,
                    Aad::from(aad),
                    tag.as_slice(),
                    buffer,
                )
                .map_err(aws_err)?;
                Ok(())
            }
        }
    };
}

impl_engine!(EngineAes128Gcm, &AES_128_GCM, U16);
impl_engine!(EngineChaCha20Poly1305, &CHACHA20_POLY1305, U32);

/// DHKEM AEAD suite marker: AES-128-GCM on aws-lc.  Same `AEAD_ID` as
/// `hpke::aead::AesGcm128`, so the wire format and the (shared, unchanged)
/// key schedule are bit-for-bit compatible.
#[derive(Clone, Copy)]
pub struct AwsAesGcm128;

impl ::hpke::aead::Aead for AwsAesGcm128 {
    type AeadImpl = EngineAes128Gcm;
    const AEAD_ID: u16 = 1;
}

/// DHKEM AEAD suite marker: ChaCha20-Poly1305 on aws-lc.
#[derive(Clone, Copy)]
pub struct AwsChaCha20Poly1305;

impl ::hpke::aead::Aead for AwsChaCha20Poly1305 {
    type AeadImpl = EngineChaCha20Poly1305;
    const AEAD_ID: u16 = 3;
}

/// A switch-hitting AEAD that uses a selected primitive.  This is the
/// response-direction engine: it is keyed off an HPKE exporter secret
/// rather than an HPKE context, and mirrors `crate::rh::aead::Aead`.
pub struct Aead {
    mode: Mode,
    algorithm: AeadId,
    engine: LessSafeKey,
    nonce_base: [u8; NONCE_LEN],
    seq: SequenceNumber,
}

impl Aead {
    #[allow(clippy::unnecessary_wraps)]
    pub fn new(
        mode: Mode,
        algorithm: AeadId,
        key: &SymKey,
        nonce_base: [u8; NONCE_LEN],
    ) -> Res<Self> {
        let alg = match algorithm {
            AeadId::Aes128Gcm => &AES_128_GCM,
            AeadId::Aes256Gcm => &AES_256_GCM,
            AeadId::ChaCha20Poly1305 => &CHACHA20_POLY1305,
        };
        let engine = try_new_key(alg, key.as_ref())?;
        Ok(Self {
            mode,
            algorithm,
            engine,
            nonce_base,
            seq: 0,
        })
    }

    #[cfg(test)]
    #[allow(clippy::unnecessary_wraps)]
    pub(crate) fn import_key(_alg: AeadId, k: &[u8]) -> Res<SymKey> {
        Ok(SymKey::from(k))
    }

    fn nonce(&self, seq: SequenceNumber) -> [u8; NONCE_LEN] {
        let mut nonce = self.nonce_base;
        for (i, n) in nonce.iter_mut().rev().take(COUNTER_LEN).enumerate() {
            *n ^= u8::try_from((seq >> (8 * i)) & 0xff).unwrap();
        }
        nonce
    }

    pub fn open_seq(&mut self, aad: &[u8], seq: SequenceNumber, ct: &[u8]) -> Res<Vec<u8>> {
        assert_eq!(self.mode, Mode::Decrypt);
        // Match the RustCrypto engines: a payload shorter than the tag is
        // a decrypt error, not a panic.
        if ct.len() < TAG_LEN {
            return Err(AeadError.into());
        }
        let (ciphertext, tag) = ct.split_at(ct.len() - TAG_LEN);
        let mut pt = ciphertext.to_vec();
        let n = mk_nonce(&self.nonce(seq))?;
        self.engine
            .open_in_place_separate_tag(n, Aad::from(aad), tag, &mut pt)
            .map_err(aws_err)?;
        Ok(pt)
    }
}

impl Encrypt for Aead {
    fn seal(&mut self, aad: &[u8], pt: &[u8]) -> Res<Vec<u8>> {
        assert_eq!(self.mode, Mode::Encrypt);
        let nonce = self.nonce(self.seq);
        self.seq += 1;
        let mut out = Vec::with_capacity(pt.len() + TAG_LEN);
        out.extend_from_slice(pt);
        let tag = self
            .engine
            .seal_in_place_separate_tag(mk_nonce(&nonce)?, Aad::from(aad), &mut out)
            .map_err(aws_err)?;
        out.extend_from_slice(tag.as_ref());
        Ok(out)
    }

    #[allow(unused)]
    fn alg(&self) -> AeadId {
        self.algorithm
    }
}

impl Decrypt for Aead {
    fn open(&mut self, aad: &[u8], ct: &[u8]) -> Res<Vec<u8>> {
        let res = self.open_seq(aad, self.seq, ct);
        self.seq += 1;
        res
    }

    #[allow(unused)]
    fn alg(&self) -> AeadId {
        self.algorithm
    }
}
