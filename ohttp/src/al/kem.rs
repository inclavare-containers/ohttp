use std::fmt::{self, Debug};

use ::hpke::generic_array::{typenum::U32, GenericArray};
use ::hpke::kdf::{extract_and_expand, labeled_extract, HkdfSha256, LabeledExpand};
use ::hpke::kem::{Kem as KemTrait, SharedSecret};
use ::hpke::rand_core::{CryptoRng, RngCore};
use ::hpke::{Deserializable, HpkeError, Serializable};

/// DHKEM(X25519, HKDF-SHA256) on top of aws-lc's raw `X25519`.
///
/// The scalar-multiply cost dominates the HPKE setup on this path
/// (Stage-0 profile: 24-38% of request CPU per host went through dalek
/// scalar math); aws-lc's field arithmetic is 2-3x faster than dalek's
/// ladder on the bench hosts.  Everything else (the labeled HKDF calls
/// that make up `ExtractAndExpand` and `DeriveKeyPair`) reuses
/// `rust_hpke`'s own `pub` helpers, so the bytes this KEM produces are
/// identical to `hpke::kem::X25519HkdfSha256` by construction.
pub struct AwsX25519HkdfSha256;

/// `suite_id = concat("KEM", I2OSP(kem_id, 2))` from RFC 9180 §4.1.
const KEM_SUITE_ID: &[u8] = b"KEM\x00\x20";

const NPK: usize = 32;

#[derive(Clone, PartialEq, Eq)]
pub struct PublicKey([u8; NPK]);

impl Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "PublicKey {}", hex::encode(self.0))
    }
}

#[derive(Clone)]
pub struct PrivateKey {
    /// Raw (unclamped) scalar bytes, matching what dalek's `StaticSecret`
    /// stores: dalek defers the RFC 7748 clamp to multiplication time, so
    /// the stored representation is the input bytes verbatim.  PKCS#8 PEM
    /// export and `key_data` parity with the dalek backend depend on these
    /// exact bytes.
    sk: [u8; NPK],
    /// The public key derived from `sk`, cached so that `sk_to_pk` and
    /// `Decap` do not pay a base-point multiplication per request.
    pk: PublicKey,
}

impl Debug for PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if cfg!(feature = "unsafe-print-secrets") {
            return write!(f, "PrivateKey {}", hex::encode(self.sk));
        }
        write!(f, "Opaque PrivateKey")
    }
}

#[derive(Clone)]
pub struct EncappedKey(PublicKey);

/// Fixed base point (9 little-endian) for the scalar * G operation.
/// Used only by the test cross-check below; production derives the public
/// key through `X25519_public_from_private`.
#[cfg(test)]
const BASEPOINT: [u8; NPK] = {
    let mut p = [0u8; NPK];
    p[0] = 9;
    p
};

/// `X25519(scalar, u)`: the RFC 7748 function.  aws-lc applies the §5
/// clamping internally, so raw (unclamped) scalars are valid inputs,
/// exactly like dalek's `mul_clamped`.
fn x25519(scalar: &[u8; NPK], point: &[u8; NPK]) -> [u8; NPK] {
    let mut out = [0u8; NPK];
    // aws-lc returns 0 on internal allocation failure and writes an
    // all-zero buffer; the DH callers reject all-zero output, so a
    // failure surfaces as the spec-mandated abort.
    unsafe { aws_lc_sys::X25519(out.as_mut_ptr(), scalar.as_ptr(), point.as_ptr()) };
    out
}

fn base_mult(sk: &[u8; NPK]) -> PublicKey {
    let mut out = [0u8; NPK];
    // `X25519_public_from_private` is the same RFC 7748 scalar*G as passing
    // `BASEPOINT` through the generic `X25519` ladder (aws-lc applies the §5
    // clamp inside both), but it uses the base-point specialized multiply,
    // which costs ~7us on this platform versus ~25us for the generic ladder.
    unsafe { aws_lc_sys::X25519_public_from_private(out.as_mut_ptr(), sk.as_ptr()) };
    PublicKey(out)
}

/// Cross-check used only by tests: the generic-ladder derivation the
/// implementation used before the specialized base multiply existed.
#[cfg(test)]
fn base_mult_generic(sk: &[u8; NPK]) -> PublicKey {
    PublicKey(x25519(sk, &BASEPOINT))
}

/// `DH(sk, pk)` as defined by RFC 9180 §7.1: the all-zero result must
/// abort.  `None` here; the caller maps it to `EncapError`/`DecapError`
/// exactly like rust-hpke does (the observable error class is part of
/// the cross-backend parity contract).
fn dh(sk: &PrivateKey, pk: &PublicKey) -> Option<[u8; NPK]> {
    let shared = x25519(&sk.sk, &pk.0);
    if shared == [0u8; NPK] {
        return None;
    }
    Some(shared)
}

/// Zero the scalar bytes when the key is dropped, mirroring dalek's
/// `zeroize(drop)` on `StaticSecret`.
impl Drop for PrivateKey {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.sk);
    }
}

/// rust-hpke compares backend private keys in constant time
/// (`subtle::ConstantTimeEq` over `to_bytes()`); match that so error
/// paths cannot leak scalar bits through timing.
impl subtle::ConstantTimeEq for PrivateKey {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        subtle::ConstantTimeEq::ct_eq(&self.sk[..], &other.sk[..])
    }
}

impl PartialEq for PrivateKey {
    fn eq(&self, other: &Self) -> bool {
        subtle::ConstantTimeEq::ct_eq(self, other).into()
    }
}
impl Eq for PrivateKey {}

impl PrivateKey {
    /// Build from raw scalar bytes, exactly like dalek's
    /// `StaticSecret::from` (which stores the bytes and clamps at
    /// multiplication time).
    fn new(sk: [u8; NPK]) -> Self {
        let pk = base_mult(&sk);
        Self { sk, pk }
    }
}

impl Serializable for PublicKey {
    type OutputSize = U32;
    fn write_exact(&self, buf: &mut [u8]) {
        buf.copy_from_slice(&self.0);
    }
}

impl Deserializable for PublicKey {
    fn from_bytes(encoded: &[u8]) -> Result<Self, HpkeError> {
        if encoded.len() != NPK {
            return Err(HpkeError::ValidationError);
        }
        let mut arr = [0u8; NPK];
        arr.copy_from_slice(encoded);
        Ok(Self(arr))
    }
}

impl Serializable for PrivateKey {
    type OutputSize = U32;
    fn write_exact(&self, buf: &mut [u8]) {
        buf.copy_from_slice(&self.sk);
    }
}

impl Deserializable for PrivateKey {
    fn from_bytes(encoded: &[u8]) -> Result<Self, HpkeError> {
        if encoded.len() != NPK {
            return Err(HpkeError::ValidationError);
        }
        let mut arr = [0u8; NPK];
        arr.copy_from_slice(encoded);
        Ok(Self::new(arr))
    }
}

impl Serializable for EncappedKey {
    type OutputSize = U32;
    fn write_exact(&self, buf: &mut [u8]) {
        self.0.write_exact(buf);
    }
}

impl Deserializable for EncappedKey {
    fn from_bytes(encoded: &[u8]) -> Result<Self, HpkeError> {
        Ok(Self(PublicKey::from_bytes(encoded)?))
    }
}

/// RFC 9180 §4.1 `ExtractAndExpand(dh, kemContext)` for this KEM:
/// `LabeledExtract("", "eae_prk", dh)` then `LabeledExpand("shared_secret",
/// kemContext)`, both under the KEM suite id.
fn extract_and_expand_shared(
    dh_bytes: &[u8],
    kem_context: &[u8],
) -> SharedSecret<AwsX25519HkdfSha256> {
    let mut shared_secret = SharedSecret::<AwsX25519HkdfSha256>(GenericArray::<u8, U32>::default());
    extract_and_expand::<HkdfSha256>(
        dh_bytes,
        KEM_SUITE_ID,
        kem_context,
        shared_secret.0.as_mut_slice(),
    )
    .expect("shared secret is way too big");
    shared_secret
}

impl KemTrait for AwsX25519HkdfSha256 {
    type PublicKey = PublicKey;
    type PrivateKey = PrivateKey;
    type EncappedKey = EncappedKey;
    type NSecret = U32;

    const KEM_ID: u16 = 0x0020;

    fn sk_to_pk(sk: &PrivateKey) -> PublicKey {
        sk.pk.clone()
    }

    /// RFC 9180 §7.1.3: `sk = LabeledExpand("sk", DeriveKeyPair IKM, Nsk)`
    /// then the X25519 clamp.  Byte-identical to the rust-hpke dalek
    /// implementation: the expand output is compared before clamping in
    /// the KAT test, the public key after.
    fn derive_keypair(ikm: &[u8]) -> (PrivateKey, PublicKey) {
        let (_, hkdf_ctx) = labeled_extract::<HkdfSha256>(&[], KEM_SUITE_ID, b"dkp_prk", ikm);
        let mut buf = [0u8; NPK];
        hkdf_ctx
            .labeled_expand(KEM_SUITE_ID, b"sk", &[], &mut buf)
            .expect("32 bytes is way too small");
        let sk = PrivateKey::new(buf);
        let pk = sk.pk.clone();
        (sk, pk)
    }

    /// `Encap`/`AuthEncap` from RFC 9180 §4.1.  The ephemeral key is
    /// generated through `derive_keypair` from RNG-fed keying material
    /// (the `Kem::gen_keypair` default path in rust-hpke), which keeps
    /// `encap` deterministic under a given `csprng` so the RFC 9180
    /// vectors can drive it.
    fn encap<R: CryptoRng + RngCore>(
        pk_recip: &PublicKey,
        sender_id_keypair: Option<(&PrivateKey, &PublicKey)>,
        csprng: &mut R,
    ) -> Result<(SharedSecret<Self>, EncappedKey), HpkeError> {
        let mut ikm: GenericArray<u8, U32> = GenericArray::default();
        csprng.fill_bytes(&mut ikm);
        let (sk_eph, _) = Self::derive_keypair(&ikm);
        encap_with_eph(pk_recip, sender_id_keypair, &sk_eph)
    }

    /// `Decap`/`AuthDecap` from RFC 9180 §4.1.  `pk_recip` comes from the
    /// cached `sk.pk`, so this performs one X25519 per request in Base
    /// mode (two in Auth mode) and no base-point multiplication.
    fn decap(
        sk_recip: &PrivateKey,
        pk_sender_id: Option<&PublicKey>,
        encapped_key: &EncappedKey,
    ) -> Result<SharedSecret<Self>, HpkeError> {
        let kex_res_eph = dh(sk_recip, &encapped_key.0).ok_or(HpkeError::DecapError)?;

        let mut kem_context = [0u8; 3 * NPK];
        kem_context[..NPK].copy_from_slice(&encapped_key.0 .0);
        kem_context[NPK..2 * NPK].copy_from_slice(&sk_recip.pk.0);
        let mut dh_bytes = [0u8; 2 * NPK];
        dh_bytes[..NPK].copy_from_slice(&kex_res_eph);
        let (kem_context_len, dh_len) = if let Some(pk_sender_id) = pk_sender_id {
            kem_context[2 * NPK..].copy_from_slice(&pk_sender_id.0);
            let kex_res_identity = dh(sk_recip, pk_sender_id).ok_or(HpkeError::DecapError)?;
            dh_bytes[NPK..].copy_from_slice(&kex_res_identity);
            (3 * NPK, 2 * NPK)
        } else {
            (2 * NPK, NPK)
        };

        Ok(extract_and_expand_shared(
            &dh_bytes[..dh_len],
            &kem_context[..kem_context_len],
        ))
    }
}

/// `Encap`/`AuthEncap` with a caller-provided ephemeral key.  This is the
/// seam the RFC 9180 known-answer tests drive: the vectors pin `skE`, and
/// production `encap` reaches the same code through a deterministic
/// keypair derivation.
pub(crate) fn encap_with_eph(
    pk_recip: &PublicKey,
    sender_id_keypair: Option<(&PrivateKey, &PublicKey)>,
    sk_eph: &PrivateKey,
) -> Result<(SharedSecret<AwsX25519HkdfSha256>, EncappedKey), HpkeError> {
    let kex_res_eph = dh(sk_eph, pk_recip).ok_or(HpkeError::EncapError)?;
    let encapped_key = EncappedKey(sk_eph.pk.clone());

    let mut kem_context = [0u8; 3 * NPK];
    kem_context[..NPK].copy_from_slice(&encapped_key.0 .0);
    kem_context[NPK..2 * NPK].copy_from_slice(&pk_recip.0);
    let mut dh_bytes = [0u8; 2 * NPK];
    dh_bytes[..NPK].copy_from_slice(&kex_res_eph);
    let (kem_context_len, dh_len) = if let Some((sk_sender_id, pk_sender_id)) = sender_id_keypair {
        kem_context[2 * NPK..].copy_from_slice(&pk_sender_id.0);
        let kex_res_identity = dh(sk_sender_id, pk_recip).ok_or(HpkeError::EncapError)?;
        dh_bytes[NPK..].copy_from_slice(&kex_res_identity);
        (3 * NPK, 2 * NPK)
    } else {
        (2 * NPK, NPK)
    };

    Ok((
        extract_and_expand_shared(&dh_bytes[..dh_len], &kem_context[..kem_context_len]),
        encapped_key,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `X25519_public_from_private` (specialized base multiply) must agree
    /// byte-for-byte with the generic ladder evaluated at the base point for
    /// every scalar, including the all-zero and all-one edge inputs.  This
    /// is the parity contract that keeps `derive_keypair`'s `enc` bytes, and
    /// therefore the whole wire format, unchanged.
    #[test]
    fn base_mult_matches_generic_ladder() {
        let sk = [0u8; NPK];
        assert_eq!(base_mult(&sk), base_mult_generic(&sk));
        let sk = [0xff; NPK];
        assert_eq!(base_mult(&sk), base_mult_generic(&sk));
        let mut state = 0x853c_49e6_74fe_f1d1u64;
        let mut sk = [0u8; NPK];
        for _ in 0..4096 {
            for b in sk.iter_mut() {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                *b = (state & 0xff) as u8;
            }
            assert_eq!(base_mult(&sk), base_mult_generic(&sk), "sk {sk:?}");
        }
    }
}
