//! Known-answer and cross-backend parity tests for the aws-lc backend.
//!
//! RFC 9180 vectors pin each layer the aws-lc backend replaces:
//! `derive_keypair` (labeled HKDF + clamp + base multiply),
//! `encap_with_eph`/`decap` (DH + `ExtractAndExpand`), and the AES-128-GCM
//! engine at every sequence value the chunk stream reaches.  The shared
//! rust-hpke key schedule above them is upstream's own qualified code.
//! Cross-backend tests then pin that both backends agree byte-for-byte,
//! which is the interop property TNG's ingress<->egress hop relies on.

use ::aead::{AeadInPlace, KeyInit};
use ::hpke::{
    aead::{AeadCtxR, AeadTag, AesGcm128},
    generic_array::{typenum::U16, GenericArray},
    kdf::{labeled_extract, HkdfSha256, LabeledExpand},
    kem::{Kem as KemTrait, X25519HkdfSha256},
    Deserializable, OpModeR, OpModeS, Serializable,
};

use super::aead::{self, EngineAes128Gcm};
use super::kem::{AwsX25519HkdfSha256, EncappedKey, PrivateKey, PublicKey};
use super::hpke;
use crate::{
    crypto::{Decrypt, Encrypt},
    hpke::{Aead, Kdf, Kem},
};

#[rustfmt::skip]
mod kat_vectors;
use kat_vectors::*;

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

/// RFC 9180 §4.1 `suite_id` for the KEM.
const SUITE: &[u8] = b"KEM\x00\x20";

/// Re-derive the unclamped `LabeledExpand` output the vector's `skEm`
/// carries, independent of the production code path.
fn raw_dkp_sk(ikm: &str) -> [u8; 32] {
    let (_, ctx) = labeled_extract::<HkdfSha256>(&[], SUITE, b"dkp_prk", &unhex(ikm));
    let mut buf = [0u8; 32];
    ctx.labeled_expand(SUITE, b"sk", &[], &mut buf).unwrap();
    buf
}

#[test]
fn derive_keypair_base_vector() {
    let (sk, pk) = AwsX25519HkdfSha256::derive_keypair(&unhex(BASE_IKME));
    // The vector's skEm is the pre-clamp LabeledExpand output; the
    // implementation stores the clamped scalar.
    assert_eq!(raw_dkp_sk(BASE_IKME), unhex(BASE_SKEM).as_slice());
    assert_eq!(
        sk.to_bytes().as_slice(),
        &unhex(BASE_SKEM)[..32]
    );
    assert_eq!(pk.to_bytes().as_slice(), unhex(BASE_PKEM).as_slice());

    let (sk, pk) = AwsX25519HkdfSha256::derive_keypair(&unhex(BASE_IKMR));
    assert_eq!(
        sk.to_bytes().as_slice(),
        &unhex(BASE_SKRM)[..32]
    );
    assert_eq!(pk.to_bytes().as_slice(), unhex(BASE_PKRM).as_slice());
}

#[test]
fn derive_keypair_auth_vector() {
    let (sk, pk) = AwsX25519HkdfSha256::derive_keypair(&unhex(AUTH_IKMS));
    assert_eq!(
        sk.to_bytes().as_slice(),
        &unhex(AUTH_SKSM)[..32]
    );
    assert_eq!(pk.to_bytes().as_slice(), unhex(AUTH_PKSM).as_slice());
}

#[test]
fn encap_decap_base_vector() {
    let pk_r = PublicKey::from_bytes(&unhex(BASE_PKRM)).unwrap();
    let sk_e = PrivateKey::from_bytes(&unhex(BASE_SKEM)).unwrap();
    let sk_r = PrivateKey::from_bytes(&unhex(BASE_SKRM)).unwrap();

    let (shared, enc) =
        super::kem::encap_with_eph(&pk_r, None, &sk_e).expect("encap_with_eph base");
    assert_eq!(enc.to_bytes().as_slice(), unhex(BASE_ENC).as_slice());
    assert_eq!(shared.0.as_slice(), unhex(BASE_SHARED_SECRET).as_slice());

    let opened = AwsX25519HkdfSha256::decap(&sk_r, None, &enc).expect("decap base");
    assert_eq!(opened.0.as_slice(), unhex(BASE_SHARED_SECRET).as_slice());
}

#[test]
fn encap_decap_auth_vector() {
    let pk_r = PublicKey::from_bytes(&unhex(AUTH_PKRM)).unwrap();
    let sk_e = PrivateKey::from_bytes(&unhex(AUTH_SKEM)).unwrap();
    let sk_r = PrivateKey::from_bytes(&unhex(AUTH_SKRM)).unwrap();
    let sk_s = PrivateKey::from_bytes(&unhex(AUTH_SKSM)).unwrap();
    let pk_s = PublicKey::from_bytes(&unhex(AUTH_PKSM)).unwrap();

    let (shared, enc) =
        super::kem::encap_with_eph(&pk_r, Some((&sk_s, &pk_s)), &sk_e).expect("encap auth");
    assert_eq!(enc.to_bytes().as_slice(), unhex(AUTH_ENC).as_slice());
    assert_eq!(shared.0.as_slice(), unhex(AUTH_SHARED_SECRET).as_slice());

    let opened = AwsX25519HkdfSha256::decap(&sk_r, Some(&pk_s), &enc).expect("decap auth");
    assert_eq!(opened.0.as_slice(), unhex(AUTH_SHARED_SECRET).as_slice());
}

/// The vector `encryptions` entries carry the per-sequence nonce directly;
/// drive the engine through both directions at those sequence points.
#[test]
fn aead_engine_vectors() {
    let kb = GenericArray::<u8, U16>::clone_from_slice(&unhex(BASE_KEY));
    let key = EngineAes128Gcm::new(&kb);
    for (nonce_hex, aad, pt, ct) in BASE_ENCRYPTS {
        let nonce = GenericArray::clone_from_slice(&unhex(nonce_hex));
        let aad = unhex(aad);
        let plaintext = unhex(pt);
        let ciphertext = unhex(ct);

        let mut buf = plaintext.clone();
        let tag = key
            .encrypt_in_place_detached(&nonce, &aad, &mut buf)
            .expect("seal");
        let mut sealed = buf.clone();
        sealed.extend_from_slice(tag.as_slice());
        assert_eq!(sealed, ciphertext, "sealed bytes must match the vector");

        let mut opened = buf.clone();
        key.decrypt_in_place_detached(
            &nonce,
            &aad,
            &mut opened,
            &GenericArray::clone_from_slice(&ciphertext[ciphertext.len() - 16..]),
        )
        .expect("open");
        assert_eq!(opened, plaintext);
    }
}

/// The standalone response-direction `Aead` applies the sequence-number
/// nonce mask itself; seal/open each vector entry at its own sequence.
#[test]
fn standalone_aead_vector_sequence() {
    crate::init();
    let nonce_base: [u8; 12] = unhex(BASE_BASE_NONCE)[..].try_into().unwrap();
    let k = aead::Aead::import_key(Aead::Aes128Gcm, &unhex(BASE_KEY)).unwrap();
    let mut enc = aead::Aead::new(aead::Mode::Encrypt, Aead::Aes128Gcm, &k, nonce_base).unwrap();
    let mut dec = aead::Aead::new(aead::Mode::Decrypt, Aead::Aes128Gcm, &k, nonce_base).unwrap();
    // The first six `encryptions` entries are sequence 0..5.
    for (seq, (nonce, aad, pt, ct)) in BASE_ENCRYPTS[..6].iter().enumerate() {
        let (nonce, aad, pt, ct) = (unhex(nonce), unhex(aad), unhex(pt), unhex(ct));
        // The standalone mask must agree with the vector's per-seq nonce:
        // XOR the big-endian sequence number into the trailing bytes.
        let mut expect = nonce_base;
        let s = seq as u64;
        for (i, b) in expect.iter_mut().rev().take(8).enumerate() {
            *b ^= ((s >> (8 * i)) & 0xff) as u8;
        }
        assert_eq!(expect.to_vec(), nonce, "nonce mask at seq {seq}");
        let sealed = enc.seal(&aad, &pt).unwrap();
        assert_eq!(sealed, ct);
        let opened = dec.open(&aad, &ct).unwrap();
        assert_eq!(opened, pt);
    }
}

#[test]
fn derive_keypair_matches_rust_hpke_backend() {
    // Independent of the vectors: same ikm, both backends, same bytes.
    for seed in 0..8u8 {
        let ikm = vec![seed; 32];
        let (sk_a, pk_a) = AwsX25519HkdfSha256::derive_keypair(&ikm);
        let (sk_b, pk_b) = X25519HkdfSha256::derive_keypair(&ikm);
        assert_eq!(sk_a.to_bytes().as_slice(), sk_b.to_bytes().as_slice());
        assert_eq!(pk_a.to_bytes().as_slice(), pk_b.to_bytes().as_slice());
    }
}

#[test]
fn decap_matches_rust_hpke_backend() {
    // Same skR bytes, same `enc`: both backends must reach the same
    // shared secret.  This is the wire interop property.
    let cases = [
        (BASE_SKRM, BASE_ENC, None, BASE_SHARED_SECRET),
        (AUTH_SKRM, AUTH_ENC, Some(AUTH_PKSM), AUTH_SHARED_SECRET),
    ];
    for (sk_r, enc, pk_s, shared) in cases {
        let enc_bytes = unhex(enc);
        let sk_ours = PrivateKey::from_bytes(&unhex(sk_r)).unwrap();
        let pks_ours = pk_s.map(|h| PublicKey::from_bytes(&unhex(h)).unwrap());
        let ours = AwsX25519HkdfSha256::decap(
            &sk_ours,
            pks_ours.as_ref(),
            &EncappedKey::from_bytes(&enc_bytes).unwrap(),
        )
        .unwrap();

        let sk_them = <X25519HkdfSha256 as KemTrait>::PrivateKey::from_bytes(&unhex(sk_r)).unwrap();
        let pks_them =
            pk_s.map(|h| <X25519HkdfSha256 as KemTrait>::PublicKey::from_bytes(&unhex(h)).unwrap());
        let theirs = X25519HkdfSha256::decap(
            &sk_them,
            pks_them.as_ref(),
            &<X25519HkdfSha256 as KemTrait>::EncappedKey::from_bytes(&enc_bytes).unwrap(),
        )
        .unwrap();

        assert_eq!(ours.0.as_slice(), theirs.0.as_slice());
        assert_eq!(ours.0.as_slice(), unhex(shared).as_slice());
    }
}

/// Deterministic through the csprng: both backends generate the ephemeral
/// keypair from 32 drawn bytes, so identical streams give identical `enc`
/// and shared secret.  The aws-lc decap also opens the rust-hpke enc.
struct Fixed(u64);
impl ::hpke::rand_core::RngCore for Fixed {
    fn next_u32(&mut self) -> u32 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        (self.0 >> 32) as u32
    }
    fn next_u64(&mut self) -> u64 {
        u64::from(self.next_u32())
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        for d in dest {
            *d = (self.next_u32() & 0xff) as u8;
        }
    }
}
impl ::hpke::rand_core::CryptoRng for Fixed {}

#[test]
fn encap_matches_rust_hpke_backend_under_same_csprng() {
    let (sk_b, pk_b) = X25519HkdfSha256::gen_keypair(&mut Fixed(1));
    let pk = PublicKey::from_bytes(pk_b.to_bytes().as_slice()).unwrap();

    let (shared_a, enc_a) = AwsX25519HkdfSha256::encap(&pk, None, &mut Fixed(7)).unwrap();
    let (shared_b, enc_b) = X25519HkdfSha256::encap(
        &<X25519HkdfSha256 as KemTrait>::PublicKey::from_bytes(&pk.to_bytes()).unwrap(),
        None,
        &mut Fixed(7),
    )
    .unwrap();
    assert_eq!(enc_a.to_bytes().as_slice(), enc_b.to_bytes().as_slice());
    assert_eq!(shared_a.0.as_slice(), shared_b.0.as_slice());

    let sk = PrivateKey::from_bytes(sk_b.to_bytes().as_slice()).unwrap();
    let opened = AwsX25519HkdfSha256::decap(
        &sk,
        None,
        &EncappedKey::from_bytes(&enc_b.to_bytes()).unwrap(),
    )
    .unwrap();
    assert_eq!(opened.0.as_slice(), shared_b.0.as_slice());
}

/// Base mode, AES-128-GCM: seal through the rust-hpke sender context,
/// open through the aws-lc receiver context, and the reverse.  Random
/// ephemerals, so these are round trips, not byte comparisons; the byte
/// proofs are the vectors above.
#[test]
fn cross_backend_setup_round_trip() {
    crate::init();
    let cfg = hpke::Config::new(Kem::X25519Sha256, Kdf::HkdfSha256, Aead::Aes128Gcm);

    // rust-hpke seals, aws-lc opens.
    let (sk_a, pk_a) = hpke::generate_key_pair(Kem::X25519Sha256).unwrap();
    let pk_rh =
        <X25519HkdfSha256 as KemTrait>::PublicKey::from_bytes(&pk_a.key_data().unwrap()).unwrap();
    let mut csprng = Fixed(99);
    let (enc, mut sender) =
        ::hpke::setup_sender::<AesGcm128, HkdfSha256, X25519HkdfSha256, _>(
            &OpModeS::Base,
            &pk_rh,
            b"info",
            &mut csprng,
        )
        .unwrap();
    let mut buf = b"payload".to_vec();
    let tag = sender.seal_in_place_detached(&mut buf, b"").unwrap();
    let mut sealed = buf;
    sealed.extend_from_slice(tag.to_bytes().as_slice());
    let mut receiver = hpke::HpkeR::new(cfg, &pk_a, &sk_a, &enc.to_bytes(), b"info").unwrap();
    assert_eq!(receiver.open(b"", &sealed).unwrap(), b"payload");

    // aws-lc seals, rust-hpke opens.
    let (sk_b, pk_b) = X25519HkdfSha256::gen_keypair(&mut Fixed(123));
    let pk_ours = hpke::PublicKey::X25519(PublicKey::from_bytes(pk_b.to_bytes().as_slice()).unwrap());
    let mut sender = hpke::HpkeS::new(cfg, &pk_ours, b"info").unwrap();
    let sealed = sender.seal(b"", b"payload").unwrap();
    let enc = <X25519HkdfSha256 as KemTrait>::EncappedKey::from_bytes(&sender.enc().unwrap())
        .unwrap();
    let mut receiver: AeadCtxR<AesGcm128, HkdfSha256, X25519HkdfSha256> =
        ::hpke::setup_receiver(&OpModeR::Base, &sk_b, &enc, b"info").unwrap();
    let ct_len = sealed.len() - 16;
    let mut buf = sealed[..ct_len].to_vec();
    receiver
        .open_in_place_detached(
            &mut buf,
            b"",
            &AeadTag::<AesGcm128>::from_bytes(&sealed[ct_len..]).unwrap(),
        )
        .unwrap();
    assert_eq!(buf, b"payload");
}
