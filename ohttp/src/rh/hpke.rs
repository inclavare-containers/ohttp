use std::ops::Deref;

use ::hpke as rust_hpke;
use ::rand::rng;
use log::{error, trace};
use pkcs8::{der::Encode, spki::AlgorithmIdentifier, ObjectIdentifier, PrivateKeyInfo};
use rust_hpke::{
    aead::{AeadCtxR, AeadCtxS, AeadTag, AesGcm128, AesGcm256, ChaCha20Poly1305},
    kdf::HkdfSha256,
    kem::{Kem as KemTrait, X25519HkdfSha256},
    setup_receiver, setup_sender, Deserializable, OpModeR, OpModeS, Serializable,
};

use super::SymKey;
use crate::{
    crypto::{Decrypt, Encrypt},
    hpke::{Aead, Kdf, Kem},
    Error, Res,
};

/// Configuration for `Hpke`.
#[derive(Clone, Copy)]
pub struct Config {
    kem: Kem,
    kdf: Kdf,
    aead: Aead,
}

impl Config {
    #[must_use]
    pub fn new(kem: Kem, kdf: Kdf, aead: Aead) -> Self {
        Self { kem, kdf, aead }
    }

    #[must_use]
    pub fn kem(self) -> Kem {
        self.kem
    }

    #[must_use]
    pub fn kdf(self) -> Kdf {
        self.kdf
    }

    #[must_use]
    pub fn aead(self) -> Aead {
        self.aead
    }

    #[must_use]
    pub fn supported(self) -> bool {
        // TODO support more options
        self.kdf == Kdf::HkdfSha256
            && matches!(
                self.aead,
                Aead::Aes128Gcm | Aead::Aes256Gcm | Aead::ChaCha20Poly1305
            )
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            kem: Kem::X25519Sha256,
            kdf: Kdf::HkdfSha256,
            aead: Aead::Aes128Gcm,
        }
    }
}

#[allow(clippy::large_enum_variant)]
#[derive(Clone)]
pub enum PublicKey {
    X25519(<X25519HkdfSha256 as KemTrait>::PublicKey),
}

impl PublicKey {
    #[allow(clippy::unnecessary_wraps)]
    pub fn key_data(&self) -> Res<Vec<u8>> {
        Ok(match self {
            Self::X25519(k) => Vec::from(k.to_bytes().as_slice()),
        })
    }

    pub fn from_x25519_bytes(bytes: &[u8]) -> Res<Self> {
        if bytes.len() != 32 {
            return Err(Error::InvalidKeyType);
        }
        let pk = <X25519HkdfSha256 as KemTrait>::PublicKey::from_bytes(bytes)?;
        Ok(PublicKey::X25519(pk))
    }
}

impl std::fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        if let Ok(b) = self.key_data() {
            write!(f, "PublicKey {}", hex::encode(b))
        } else {
            write!(f, "Opaque PublicKey")
        }
    }
}

#[allow(clippy::large_enum_variant)]
#[derive(Clone)]
pub enum PrivateKey {
    X25519(<X25519HkdfSha256 as KemTrait>::PrivateKey),
}

impl PrivateKey {
    pub fn from_x25519_bytes(bytes: &[u8]) -> Res<Self> {
        if bytes.len() != 32 {
            return Err(Error::InvalidKeyType);
        }
        let sk = <X25519HkdfSha256 as KemTrait>::PrivateKey::from_bytes(bytes)?;
        Ok(PrivateKey::X25519(sk))
    }
}

impl PrivateKey {
    #[allow(clippy::unnecessary_wraps)]
    pub fn key_data(&self) -> Res<Vec<u8>> {
        Ok(match self {
            Self::X25519(k) => Vec::from(k.to_bytes().as_slice()),
        })
    }
}

impl std::fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        if cfg!(feature = "unsafe-print-secrets") {
            if let Ok(b) = self.key_data() {
                return write!(f, "PrivateKey {}", hex::encode(b));
            }
        }
        write!(f, "Opaque PrivateKey")
    }
}

impl PrivateKey {
    /// Serialize a key pair to PKCS#8 PEM format for the identified KEM.
    ///
    /// Note: The resulting PKCS#8 structure does **not** include the public key.
    pub fn serialize_to_pkcs8_pem(&self) -> Res<String> {
        match self {
            PrivateKey::X25519(sk) => {
                // Step 1: Build AlgorithmIdentifier for X25519
                let alg_id = AlgorithmIdentifier {
                    oid: ObjectIdentifier::new_unwrap("1.3.101.110"), // X25519 OID
                    parameters: None,
                };

                // Step 2: Encode raw private key as OCTET STRING: [0x04, 0x20 || bytes]
                let mut private_key_bytes = Vec::with_capacity(34);
                private_key_bytes.push(0x04); // OCTET STRING tag
                private_key_bytes.push(0x20); // length = 32 bytes
                private_key_bytes.extend_from_slice(&sk.to_bytes());

                // Step 3: Construct PKCS#8 PrivateKeyInfo
                let pkcs8_info = PrivateKeyInfo {
                    algorithm: alg_id,
                    private_key: &private_key_bytes,
                    public_key: None,
                };

                // Step 4: Convert to DER
                let der_bytes = pkcs8_info.to_der().map_err(Error::PrivateKeySerialize)?;

                // Step 5: Wrap in PEM
                let pem = ::pem::Pem::new("PRIVATE KEY", der_bytes);

                Ok(::pem::encode_config(
                    &pem,
                    pem::EncodeConfig::new().set_line_ending(pem::LineEnding::LF),
                ))
            }
        }
    }
}

// TODO: Use macros here.  To do that, we needs concat_ident!(), but it's not ready.
// This is what a macro that uses concat_ident!() might produce, written out in full.
enum SenderContextX25519HkdfSha256HkdfSha256 {
    AesGcm128(Box<AeadCtxS<AesGcm128, HkdfSha256, X25519HkdfSha256>>),
    AesGcm256(Box<AeadCtxS<AesGcm256, HkdfSha256, X25519HkdfSha256>>),
    ChaCha20Poly1305(Box<AeadCtxS<ChaCha20Poly1305, HkdfSha256, X25519HkdfSha256>>),
}

enum SenderContextX25519HkdfSha256 {
    HkdfSha256(SenderContextX25519HkdfSha256HkdfSha256),
}

enum SenderContext {
    X25519HkdfSha256(SenderContextX25519HkdfSha256),
}

impl SenderContext {
    fn seal(&mut self, plaintext: &mut [u8], aad: &[u8]) -> Res<Vec<u8>> {
        Ok(match self {
            Self::X25519HkdfSha256(SenderContextX25519HkdfSha256::HkdfSha256(
                SenderContextX25519HkdfSha256HkdfSha256::AesGcm128(context),
            )) => {
                let tag = context.seal_in_place_detached(plaintext, aad)?;
                Vec::from(tag.to_bytes().as_slice())
            }
            Self::X25519HkdfSha256(SenderContextX25519HkdfSha256::HkdfSha256(
                SenderContextX25519HkdfSha256HkdfSha256::AesGcm256(context),
            )) => {
                let tag = context.seal_in_place_detached(plaintext, aad)?;
                Vec::from(tag.to_bytes().as_slice())
            }
            Self::X25519HkdfSha256(SenderContextX25519HkdfSha256::HkdfSha256(
                SenderContextX25519HkdfSha256HkdfSha256::ChaCha20Poly1305(context),
            )) => {
                let tag = context.seal_in_place_detached(plaintext, aad)?;
                Vec::from(tag.to_bytes().as_slice())
            }
        })
    }

    fn export(&self, info: &[u8], out_buf: &mut [u8]) -> Res<()> {
        match self {
            Self::X25519HkdfSha256(SenderContextX25519HkdfSha256::HkdfSha256(
                SenderContextX25519HkdfSha256HkdfSha256::AesGcm128(context),
            )) => {
                context.export(info, out_buf)?;
            }
            Self::X25519HkdfSha256(SenderContextX25519HkdfSha256::HkdfSha256(
                SenderContextX25519HkdfSha256HkdfSha256::AesGcm256(context),
            )) => {
                context.export(info, out_buf)?;
            }
            Self::X25519HkdfSha256(SenderContextX25519HkdfSha256::HkdfSha256(
                SenderContextX25519HkdfSha256HkdfSha256::ChaCha20Poly1305(context),
            )) => {
                context.export(info, out_buf)?;
            }
        }
        Ok(())
    }
}

pub trait Exporter {
    fn export(&self, info: &[u8], len: usize) -> Res<SymKey>;
}

#[allow(clippy::module_name_repetitions)]
pub struct HpkeS {
    context: SenderContext,
    enc: Vec<u8>,
    config: Config,
}

impl HpkeS {
    /// Create a new context that uses the KEM mode for sending.
    pub fn new(config: Config, pk_r: &PublicKey, info: &[u8]) -> Res<Self> {
        let mut csprng = rng();

        macro_rules! dispatch_hpkes_new {
            {
                ($c:expr, $pk:expr, $csprng:expr): [$( $(#[$meta:meta])* {
                    $kemid:path => $kem:path,
                    $kdfid:path => $kdf:path,
                    $aeadid:path => $aead:path,
                    $pke:path, $ctxt1:path, $ctxt2:path, $ctxt3:path $(,)?
                }),* $(,)?]
            } => {
                match ($c, $pk) {
                    $(
                        $(#[$meta])*
                        (
                            Config {
                                kem: $kemid,
                                kdf: $kdfid,
                                aead: $aeadid,
                            },
                            $pke(pk_r),
                        ) => {
                            let (enc, context) = setup_sender::<$aead, $kdf, $kem, _>(
                                &OpModeS::Base,
                                pk_r,
                                info,
                                $csprng,
                            )?;
                            (
                                $ctxt1($ctxt2($ctxt3(Box::new(context)))),
                                Vec::from(enc.to_bytes().as_slice()),
                            )
                        }
                    )*
                    _ => return Err(Error::InvalidKeyType),
                }
            };
        }

        let (context, enc) = dispatch_hpkes_new! { (config, pk_r, &mut csprng): [
            {
                Kem::X25519Sha256 => X25519HkdfSha256,
                Kdf::HkdfSha256 => HkdfSha256,
                Aead::Aes128Gcm => AesGcm128,
                PublicKey::X25519,
                SenderContext::X25519HkdfSha256,
                SenderContextX25519HkdfSha256::HkdfSha256,
                SenderContextX25519HkdfSha256HkdfSha256::AesGcm128,
            },
            {
                Kem::X25519Sha256 => X25519HkdfSha256,
                Kdf::HkdfSha256 => HkdfSha256,
                Aead::Aes256Gcm => AesGcm256,
                PublicKey::X25519,
                SenderContext::X25519HkdfSha256,
                SenderContextX25519HkdfSha256::HkdfSha256,
                SenderContextX25519HkdfSha256HkdfSha256::AesGcm256,
            },
            {
                Kem::X25519Sha256 => X25519HkdfSha256,
                Kdf::HkdfSha256 => HkdfSha256,
                Aead::ChaCha20Poly1305 => ChaCha20Poly1305,
                PublicKey::X25519,
                SenderContext::X25519HkdfSha256,
                SenderContextX25519HkdfSha256::HkdfSha256,
                SenderContextX25519HkdfSha256HkdfSha256::ChaCha20Poly1305,
            },
        ]};

        Ok(Self {
            context,
            enc,
            config,
        })
    }

    pub fn config(&self) -> Config {
        self.config
    }

    /// Get the encapsulated KEM secret.
    #[allow(clippy::unnecessary_wraps)]
    pub fn enc(&self) -> Res<Vec<u8>> {
        Ok(self.enc.clone())
    }
}

impl Encrypt for HpkeS {
    fn seal(&mut self, aad: &[u8], pt: &[u8]) -> Res<Vec<u8>> {
        let mut buf = pt.to_owned();
        let mut tag = self.context.seal(&mut buf, aad)?;
        buf.append(&mut tag);
        Ok(buf)
    }

    fn alg(&self) -> Aead {
        self.config.aead()
    }
}

impl Exporter for HpkeS {
    fn export(&self, info: &[u8], len: usize) -> Res<SymKey> {
        let mut buf = vec![0; len];
        self.context.export(info, &mut buf)?;
        Ok(SymKey::from(buf))
    }
}

impl Deref for HpkeS {
    type Target = Config;
    fn deref(&self) -> &Self::Target {
        &self.config
    }
}

enum ReceiverContextX25519HkdfSha256HkdfSha256 {
    AesGcm128(Box<AeadCtxR<AesGcm128, HkdfSha256, X25519HkdfSha256>>),
    AesGcm256(Box<AeadCtxR<AesGcm256, HkdfSha256, X25519HkdfSha256>>),
    ChaCha20Poly1305(Box<AeadCtxR<ChaCha20Poly1305, HkdfSha256, X25519HkdfSha256>>),
}

enum ReceiverContextX25519HkdfSha256 {
    HkdfSha256(ReceiverContextX25519HkdfSha256HkdfSha256),
}

enum ReceiverContext {
    X25519HkdfSha256(ReceiverContextX25519HkdfSha256),
}

impl ReceiverContext {
    fn open<'a>(&mut self, ciphertext: &'a mut [u8], aad: &[u8]) -> Res<&'a [u8]> {
        Ok(match self {
            Self::X25519HkdfSha256(ReceiverContextX25519HkdfSha256::HkdfSha256(
                ReceiverContextX25519HkdfSha256HkdfSha256::AesGcm128(context),
            )) => {
                if ciphertext.len() < AeadTag::<AesGcm128>::size() {
                    return Err(Error::Truncated);
                }
                let (ct, tag_slice) =
                    ciphertext.split_at_mut(ciphertext.len() - AeadTag::<AesGcm128>::size());
                let tag = AeadTag::<AesGcm128>::from_bytes(tag_slice)?;
                context.open_in_place_detached(ct, aad, &tag)?;
                ct
            }
            Self::X25519HkdfSha256(ReceiverContextX25519HkdfSha256::HkdfSha256(
                ReceiverContextX25519HkdfSha256HkdfSha256::AesGcm256(context),
            )) => {
                if ciphertext.len() < AeadTag::<AesGcm256>::size() {
                    return Err(Error::Truncated);
                }
                let (ct, tag_slice) =
                    ciphertext.split_at_mut(ciphertext.len() - AeadTag::<AesGcm256>::size());
                let tag = AeadTag::<AesGcm256>::from_bytes(tag_slice)?;
                context.open_in_place_detached(ct, aad, &tag)?;
                ct
            }
            Self::X25519HkdfSha256(ReceiverContextX25519HkdfSha256::HkdfSha256(
                ReceiverContextX25519HkdfSha256HkdfSha256::ChaCha20Poly1305(context),
            )) => {
                if ciphertext.len() < AeadTag::<ChaCha20Poly1305>::size() {
                    return Err(Error::Truncated);
                }
                let (ct, tag_slice) =
                    ciphertext.split_at_mut(ciphertext.len() - AeadTag::<ChaCha20Poly1305>::size());
                let tag = AeadTag::<ChaCha20Poly1305>::from_bytes(tag_slice)?;
                context.open_in_place_detached(ct, aad, &tag)?;
                ct
            }
        })
    }

    fn export(&self, info: &[u8], out_buf: &mut [u8]) -> Res<()> {
        match self {
            Self::X25519HkdfSha256(ReceiverContextX25519HkdfSha256::HkdfSha256(
                ReceiverContextX25519HkdfSha256HkdfSha256::AesGcm128(context),
            )) => {
                context.export(info, out_buf)?;
            }
            Self::X25519HkdfSha256(ReceiverContextX25519HkdfSha256::HkdfSha256(
                ReceiverContextX25519HkdfSha256HkdfSha256::AesGcm256(context),
            )) => {
                context.export(info, out_buf)?;
            }
            Self::X25519HkdfSha256(ReceiverContextX25519HkdfSha256::HkdfSha256(
                ReceiverContextX25519HkdfSha256HkdfSha256::ChaCha20Poly1305(context),
            )) => {
                context.export(info, out_buf)?;
            }
        }
        Ok(())
    }
}

#[allow(clippy::module_name_repetitions)]
pub struct HpkeR {
    context: ReceiverContext,
    config: Config,
}

impl HpkeR {
    /// Create a new context that uses the KEM mode for sending.
    #[allow(clippy::similar_names)]
    pub fn new(
        config: Config,
        _pk_r: &PublicKey,
        sk_r: &PrivateKey,
        enc: &[u8],
        info: &[u8],
    ) -> Res<Self> {
        macro_rules! dispatch_hpker_new {
            {
                ($c:ident, $sk:ident): [$( $(#[$meta:meta])* {
                    $kemid:path => $kem:path,
                    $kdfid:path => $kdf:path,
                    $aeadid:path => $aead:path,
                    $ske:path, $ctxt1:path, $ctxt2:path, $ctxt3:path $(,)?
            }),* $(,)?]
            } => {
                match ($c, $sk) {
                    $(
                        $(#[$meta])*
                        (
                            Config {
                                kem: $kemid,
                                kdf: $kdfid,
                                aead: $aeadid,
                            },
                            $ske(sk_r),
                        ) => {
                            let enc = <$kem as KemTrait>::EncappedKey::from_bytes(enc)?;
                            let context = setup_receiver::<$aead, $kdf, $kem>(
                                &OpModeR::Base,
                                sk_r,
                                &enc,
                                info,
                            )?;
                            $ctxt1($ctxt2($ctxt3(Box::new(context))))
                        }
                    )*
                    _ => return Err(Error::InvalidKeyType),
                }
            };
        }
        let context = dispatch_hpker_new! {(config, sk_r): [
            {
                Kem::X25519Sha256 => X25519HkdfSha256,
                Kdf::HkdfSha256 => HkdfSha256,
                Aead::Aes128Gcm => AesGcm128,
                PrivateKey::X25519,
                ReceiverContext::X25519HkdfSha256,
                ReceiverContextX25519HkdfSha256::HkdfSha256,
                ReceiverContextX25519HkdfSha256HkdfSha256::AesGcm128,
            },
            {
                Kem::X25519Sha256 => X25519HkdfSha256,
                Kdf::HkdfSha256 => HkdfSha256,
                Aead::Aes256Gcm => AesGcm256,
                PrivateKey::X25519,
                ReceiverContext::X25519HkdfSha256,
                ReceiverContextX25519HkdfSha256::HkdfSha256,
                ReceiverContextX25519HkdfSha256HkdfSha256::AesGcm256,
            },
            {
                Kem::X25519Sha256 => X25519HkdfSha256,
                Kdf::HkdfSha256 => HkdfSha256,
                Aead::ChaCha20Poly1305 => ChaCha20Poly1305,
                PrivateKey::X25519,
                ReceiverContext::X25519HkdfSha256,
                ReceiverContextX25519HkdfSha256::HkdfSha256,
                ReceiverContextX25519HkdfSha256HkdfSha256::ChaCha20Poly1305,
            },
        ]};

        Ok(Self { context, config })
    }

    #[allow(dead_code)] // used only with the `stream` feature
    pub fn config(&self) -> Config {
        self.config
    }

    pub fn decode_public_key(kem: Kem, k: &[u8]) -> Res<PublicKey> {
        Ok(match kem {
            Kem::X25519Sha256 => {
                PublicKey::X25519(<X25519HkdfSha256 as KemTrait>::PublicKey::from_bytes(k)?)
            }
        })
    }
}

impl Decrypt for HpkeR {
    fn open(&mut self, aad: &[u8], ct: &[u8]) -> Res<Vec<u8>> {
        let mut buf = ct.to_owned();
        let pt_len = self.context.open(&mut buf, aad)?.len();
        buf.truncate(pt_len);
        Ok(buf)
    }

    fn alg(&self) -> Aead {
        self.config.aead()
    }
}

impl Exporter for HpkeR {
    fn export(&self, info: &[u8], len: usize) -> Res<SymKey> {
        let mut buf = vec![0; len];
        self.context.export(info, &mut buf)?;
        Ok(SymKey::from(buf))
    }
}

impl Deref for HpkeR {
    type Target = Config;
    fn deref(&self) -> &Self::Target {
        &self.config
    }
}

// ── Auth Mode Sender ──────────────────────────────────────────────────

#[allow(dead_code)]
enum AuthSenderContextX25519HkdfSha256HkdfSha256 {
    AesGcm128(Box<AeadCtxS<AesGcm128, HkdfSha256, X25519HkdfSha256>>),
    AesGcm256(Box<AeadCtxS<AesGcm256, HkdfSha256, X25519HkdfSha256>>),
    ChaCha20Poly1305(Box<AeadCtxS<ChaCha20Poly1305, HkdfSha256, X25519HkdfSha256>>),
}

#[allow(dead_code)]
enum AuthSenderContextX25519HkdfSha256 {
    HkdfSha256(AuthSenderContextX25519HkdfSha256HkdfSha256),
}

#[allow(dead_code)]
enum AuthSenderContext {
    X25519HkdfSha256(AuthSenderContextX25519HkdfSha256),
}

impl AuthSenderContext {
    fn seal(&mut self, plaintext: &mut [u8], aad: &[u8]) -> Res<Vec<u8>> {
        Ok(match self {
            Self::X25519HkdfSha256(AuthSenderContextX25519HkdfSha256::HkdfSha256(
                AuthSenderContextX25519HkdfSha256HkdfSha256::AesGcm128(context),
            )) => {
                let tag = context.seal_in_place_detached(plaintext, aad)?;
                Vec::from(tag.to_bytes().as_slice())
            }
            Self::X25519HkdfSha256(AuthSenderContextX25519HkdfSha256::HkdfSha256(
                AuthSenderContextX25519HkdfSha256HkdfSha256::AesGcm256(context),
            )) => {
                let tag = context.seal_in_place_detached(plaintext, aad)?;
                Vec::from(tag.to_bytes().as_slice())
            }
            Self::X25519HkdfSha256(AuthSenderContextX25519HkdfSha256::HkdfSha256(
                AuthSenderContextX25519HkdfSha256HkdfSha256::ChaCha20Poly1305(context),
            )) => {
                let tag = context.seal_in_place_detached(plaintext, aad)?;
                Vec::from(tag.to_bytes().as_slice())
            }
        })
    }

    fn export(&self, info: &[u8], out_buf: &mut [u8]) -> Res<()> {
        match self {
            Self::X25519HkdfSha256(AuthSenderContextX25519HkdfSha256::HkdfSha256(
                AuthSenderContextX25519HkdfSha256HkdfSha256::AesGcm128(context),
            )) => {
                context.export(info, out_buf)?;
            }
            Self::X25519HkdfSha256(AuthSenderContextX25519HkdfSha256::HkdfSha256(
                AuthSenderContextX25519HkdfSha256HkdfSha256::AesGcm256(context),
            )) => {
                context.export(info, out_buf)?;
            }
            Self::X25519HkdfSha256(AuthSenderContextX25519HkdfSha256::HkdfSha256(
                AuthSenderContextX25519HkdfSha256HkdfSha256::ChaCha20Poly1305(context),
            )) => {
                context.export(info, out_buf)?;
            }
        }
        Ok(())
    }
}

/// HPKE sender context for Auth mode.
///
/// Unlike [`HpkeS`] which uses Base mode, this incorporates the sender's
/// public key into the KDF, enabling the receiver to authenticate the sender.
#[allow(dead_code)]
#[allow(clippy::module_name_repetitions)]
pub struct AuthHpkeS {
    context: AuthSenderContext,
    enc: Vec<u8>,
    config: Config,
}

#[allow(dead_code)]
impl AuthHpkeS {
    /// Create a new Auth-mode sender context.
    ///
    /// Derives the sender public key from `sk_s` and uses `OpModeS::Auth(pk_s)`.
    pub fn new(config: Config, pk_r: &PublicKey, sk_s: &PrivateKey, info: &[u8]) -> Res<Self> {
        let mut csprng = rng();

        macro_rules! dispatch_auth_hpkes_new {
            {
                ($c:expr, $pk:expr, $sk:expr, $csprng:expr): [$( $(#[$meta:meta])* {
                    $kemid:path => $kem:path,
                    $kdfid:path => $kdf:path,
                    $aeadid:path => $aead:path,
                    $pke:path, $ske:path, $ctxt1:path, $ctxt2:path, $ctxt3:path $(,)?
                }),* $(,)?]
            } => {
                match ($c, $pk, $sk) {
                    $(
                        $(#[$meta])*
                        (
                            Config { kem: $kemid, kdf: $kdfid, aead: $aeadid },
                            $pke(pk_r),
                            $ske(sk_s),
                        ) => {
                            let pk_s = <$kem as KemTrait>::sk_to_pk(sk_s);
                            let (enc, context) = setup_sender::<$aead, $kdf, $kem, _>(
                                &OpModeS::Auth((sk_s.clone(), pk_s)),
                                pk_r,
                                info,
                                $csprng,
                            )?;
                            (
                                $ctxt1($ctxt2($ctxt3(Box::new(context)))),
                                Vec::from(enc.to_bytes().as_slice()),
                            )
                        }
                    )*
                    _ => return Err(Error::InvalidKeyType),
                }
            };
        }

        let (context, enc) = dispatch_auth_hpkes_new! { (config, pk_r, sk_s, &mut csprng): [
            {
                Kem::X25519Sha256 => X25519HkdfSha256,
                Kdf::HkdfSha256 => HkdfSha256,
                Aead::Aes128Gcm => AesGcm128,
                PublicKey::X25519,
                PrivateKey::X25519,
                AuthSenderContext::X25519HkdfSha256,
                AuthSenderContextX25519HkdfSha256::HkdfSha256,
                AuthSenderContextX25519HkdfSha256HkdfSha256::AesGcm128,
            },
            {
                Kem::X25519Sha256 => X25519HkdfSha256,
                Kdf::HkdfSha256 => HkdfSha256,
                Aead::Aes256Gcm => AesGcm256,
                PublicKey::X25519,
                PrivateKey::X25519,
                AuthSenderContext::X25519HkdfSha256,
                AuthSenderContextX25519HkdfSha256::HkdfSha256,
                AuthSenderContextX25519HkdfSha256HkdfSha256::AesGcm256,
            },
            {
                Kem::X25519Sha256 => X25519HkdfSha256,
                Kdf::HkdfSha256 => HkdfSha256,
                Aead::ChaCha20Poly1305 => ChaCha20Poly1305,
                PublicKey::X25519,
                PrivateKey::X25519,
                AuthSenderContext::X25519HkdfSha256,
                AuthSenderContextX25519HkdfSha256::HkdfSha256,
                AuthSenderContextX25519HkdfSha256HkdfSha256::ChaCha20Poly1305,
            },
        ]};

        Ok(Self {
            context,
            enc,
            config,
        })
    }

    pub fn config(&self) -> Config {
        self.config
    }

    /// Get the encapsulated KEM secret.
    #[allow(clippy::unnecessary_wraps)]
    pub fn enc(&self) -> Res<Vec<u8>> {
        Ok(self.enc.clone())
    }
}

impl Encrypt for AuthHpkeS {
    fn seal(&mut self, aad: &[u8], pt: &[u8]) -> Res<Vec<u8>> {
        let mut buf = pt.to_owned();
        let mut tag = self.context.seal(&mut buf, aad)?;
        buf.append(&mut tag);
        Ok(buf)
    }

    fn alg(&self) -> Aead {
        self.config.aead()
    }
}

impl Exporter for AuthHpkeS {
    fn export(&self, info: &[u8], len: usize) -> Res<SymKey> {
        let mut buf = vec![0; len];
        self.context.export(info, &mut buf)?;
        Ok(SymKey::from(buf))
    }
}

impl Deref for AuthHpkeS {
    type Target = Config;
    fn deref(&self) -> &Self::Target {
        &self.config
    }
}

// ── Auth Mode Receiver ────────────────────────────────────────────────

#[allow(dead_code)]
enum AuthReceiverContextX25519HkdfSha256HkdfSha256 {
    AesGcm128(Box<AeadCtxR<AesGcm128, HkdfSha256, X25519HkdfSha256>>),
    AesGcm256(Box<AeadCtxR<AesGcm256, HkdfSha256, X25519HkdfSha256>>),
    ChaCha20Poly1305(Box<AeadCtxR<ChaCha20Poly1305, HkdfSha256, X25519HkdfSha256>>),
}

#[allow(dead_code)]
enum AuthReceiverContextX25519HkdfSha256 {
    HkdfSha256(AuthReceiverContextX25519HkdfSha256HkdfSha256),
}

#[allow(dead_code)]
enum AuthReceiverContext {
    X25519HkdfSha256(AuthReceiverContextX25519HkdfSha256),
}

impl AuthReceiverContext {
    fn open<'a>(&mut self, ciphertext: &'a mut [u8], aad: &[u8]) -> Res<&'a [u8]> {
        Ok(match self {
            Self::X25519HkdfSha256(AuthReceiverContextX25519HkdfSha256::HkdfSha256(
                AuthReceiverContextX25519HkdfSha256HkdfSha256::AesGcm128(context),
            )) => {
                if ciphertext.len() < AeadTag::<AesGcm128>::size() {
                    return Err(Error::Truncated);
                }
                let (ct, tag_slice) =
                    ciphertext.split_at_mut(ciphertext.len() - AeadTag::<AesGcm128>::size());
                let tag = AeadTag::<AesGcm128>::from_bytes(tag_slice)?;
                context.open_in_place_detached(ct, aad, &tag)?;
                ct
            }
            Self::X25519HkdfSha256(AuthReceiverContextX25519HkdfSha256::HkdfSha256(
                AuthReceiverContextX25519HkdfSha256HkdfSha256::AesGcm256(context),
            )) => {
                if ciphertext.len() < AeadTag::<AesGcm256>::size() {
                    return Err(Error::Truncated);
                }
                let (ct, tag_slice) =
                    ciphertext.split_at_mut(ciphertext.len() - AeadTag::<AesGcm256>::size());
                let tag = AeadTag::<AesGcm256>::from_bytes(tag_slice)?;
                context.open_in_place_detached(ct, aad, &tag)?;
                ct
            }
            Self::X25519HkdfSha256(AuthReceiverContextX25519HkdfSha256::HkdfSha256(
                AuthReceiverContextX25519HkdfSha256HkdfSha256::ChaCha20Poly1305(context),
            )) => {
                if ciphertext.len() < AeadTag::<ChaCha20Poly1305>::size() {
                    return Err(Error::Truncated);
                }
                let (ct, tag_slice) =
                    ciphertext.split_at_mut(ciphertext.len() - AeadTag::<ChaCha20Poly1305>::size());
                let tag = AeadTag::<ChaCha20Poly1305>::from_bytes(tag_slice)?;
                context.open_in_place_detached(ct, aad, &tag)?;
                ct
            }
        })
    }

    fn export(&self, info: &[u8], out_buf: &mut [u8]) -> Res<()> {
        match self {
            Self::X25519HkdfSha256(AuthReceiverContextX25519HkdfSha256::HkdfSha256(
                AuthReceiverContextX25519HkdfSha256HkdfSha256::AesGcm128(context),
            )) => {
                context.export(info, out_buf)?;
            }
            Self::X25519HkdfSha256(AuthReceiverContextX25519HkdfSha256::HkdfSha256(
                AuthReceiverContextX25519HkdfSha256HkdfSha256::AesGcm256(context),
            )) => {
                context.export(info, out_buf)?;
            }
            Self::X25519HkdfSha256(AuthReceiverContextX25519HkdfSha256::HkdfSha256(
                AuthReceiverContextX25519HkdfSha256HkdfSha256::ChaCha20Poly1305(context),
            )) => {
                context.export(info, out_buf)?;
            }
        }
        Ok(())
    }
}

/// HPKE receiver context for Auth mode.
///
/// Unlike [`HpkeR`] which uses Base mode, this requires the sender's public
/// key and uses `OpModeR::Auth(pk_s)`, enabling sender authentication.
#[allow(dead_code)]
#[allow(clippy::module_name_repetitions)]
pub struct AuthHpkeR {
    context: AuthReceiverContext,
    config: Config,
}

#[allow(dead_code)]
impl AuthHpkeR {
    /// Create a new Auth-mode receiver context.
    ///
    /// Requires the sender's public key `pk_s` for authentication.
    #[allow(clippy::similar_names)]
    pub fn new(
        config: Config,
        _pk_r: &PublicKey,
        sk_r: &PrivateKey,
        pk_s: &PublicKey,
        enc: &[u8],
        info: &[u8],
    ) -> Res<Self> {
        macro_rules! dispatch_auth_hpker_new {
            {
                ($c:ident, $sk_r:ident, $pk_s:ident): [$( $(#[$meta:meta])* {
                    $kemid:path => $kem:path,
                    $kdfid:path => $kdf:path,
                    $aeadid:path => $aead:path,
                    $ske:path, $pke:path, $ctxt1:path, $ctxt2:path, $ctxt3:path $(,)?
                }),* $(,)?]
            } => {
                match ($c, $sk_r, $pk_s) {
                    $(
                        $(#[$meta])*
                        (
                            Config { kem: $kemid, kdf: $kdfid, aead: $aeadid },
                            $ske(sk_r),
                            $pke(pk_s),
                        ) => {
                            let enc = <$kem as KemTrait>::EncappedKey::from_bytes(enc)?;
                            let context = setup_receiver::<$aead, $kdf, $kem>(
                                &OpModeR::Auth(pk_s.clone()),
                                sk_r,
                                &enc,
                                info,
                            )?;
                            $ctxt1($ctxt2($ctxt3(Box::new(context))))
                        }
                    )*
                    _ => return Err(Error::InvalidKeyType),
                }
            };
        }

        let context = dispatch_auth_hpker_new! {(config, sk_r, pk_s): [
            {
                Kem::X25519Sha256 => X25519HkdfSha256,
                Kdf::HkdfSha256 => HkdfSha256,
                Aead::Aes128Gcm => AesGcm128,
                PrivateKey::X25519,
                PublicKey::X25519,
                AuthReceiverContext::X25519HkdfSha256,
                AuthReceiverContextX25519HkdfSha256::HkdfSha256,
                AuthReceiverContextX25519HkdfSha256HkdfSha256::AesGcm128,
            },
            {
                Kem::X25519Sha256 => X25519HkdfSha256,
                Kdf::HkdfSha256 => HkdfSha256,
                Aead::Aes256Gcm => AesGcm256,
                PrivateKey::X25519,
                PublicKey::X25519,
                AuthReceiverContext::X25519HkdfSha256,
                AuthReceiverContextX25519HkdfSha256::HkdfSha256,
                AuthReceiverContextX25519HkdfSha256HkdfSha256::AesGcm256,
            },
            {
                Kem::X25519Sha256 => X25519HkdfSha256,
                Kdf::HkdfSha256 => HkdfSha256,
                Aead::ChaCha20Poly1305 => ChaCha20Poly1305,
                PrivateKey::X25519,
                PublicKey::X25519,
                AuthReceiverContext::X25519HkdfSha256,
                AuthReceiverContextX25519HkdfSha256::HkdfSha256,
                AuthReceiverContextX25519HkdfSha256HkdfSha256::ChaCha20Poly1305,
            },
        ]};

        Ok(Self { context, config })
    }

    pub fn config(&self) -> Config {
        self.config
    }
}

impl Decrypt for AuthHpkeR {
    fn open(&mut self, aad: &[u8], ct: &[u8]) -> Res<Vec<u8>> {
        let mut buf = ct.to_owned();
        let pt_len = self.context.open(&mut buf, aad)?.len();
        buf.truncate(pt_len);
        Ok(buf)
    }

    fn alg(&self) -> Aead {
        self.config.aead()
    }
}

impl Exporter for AuthHpkeR {
    fn export(&self, info: &[u8], len: usize) -> Res<SymKey> {
        let mut buf = vec![0; len];
        self.context.export(info, &mut buf)?;
        Ok(SymKey::from(buf))
    }
}

impl Deref for AuthHpkeR {
    type Target = Config;
    fn deref(&self) -> &Self::Target {
        &self.config
    }
}

/// Generate a key pair for the identified KEM.
#[allow(clippy::unnecessary_wraps)]
pub fn generate_key_pair(kem: Kem) -> Res<(PrivateKey, PublicKey)> {
    let mut csprng = rng();
    let (sk, pk) = match kem {
        Kem::X25519Sha256 => {
            let (sk, pk) = X25519HkdfSha256::gen_keypair(&mut csprng);
            (PrivateKey::X25519(sk), PublicKey::X25519(pk))
        }
    };
    trace!("Generated key pair: sk={sk:?} pk={pk:?}");
    Ok((sk, pk))
}

/// Parse a key pair from PKCS#8 PEM format for the identified KEM.
#[allow(clippy::unnecessary_wraps)]
pub fn parse_key_pair(kem: Kem, pem_data: &str) -> Res<(PrivateKey, PublicKey)> {
    // Parse PEM data
    let pem = ::pem::parse(pem_data)?;
    let pkcs8_bytes = pem.into_contents();

    // Parse PKCS#8 data to get the private key
    let pkcs8_key = ::pkcs8::PrivateKeyInfo::try_from(pkcs8_bytes.as_slice())?;

    let (sk, pk) = match kem {
        Kem::X25519Sha256 => {
            if pkcs8_key.algorithm.oid != ObjectIdentifier::new_unwrap("1.3.101.110") {
                error!("Not an X25519 private key");
                return Err(Error::InvalidKeyType);
            }

            // Extract the raw 32-byte X25519 private key from a PKCS#8 structure
            let [0x04, 0x20, private_key_bytes @ ..] = pkcs8_key.private_key else {
                error!("Invalid X25519 private key, OCTET STRING expected");
                return Err(Error::InvalidKeyType);
            };

            let sk = <X25519HkdfSha256 as KemTrait>::PrivateKey::from_bytes(private_key_bytes)?;
            let pk = hpke::kem::X25519HkdfSha256::sk_to_pk(&sk);
            (PrivateKey::X25519(sk), PublicKey::X25519(pk))
        }
    };
    trace!("Parsed key pair: sk={sk:?} pk={pk:?}");
    Ok((sk, pk))
}

#[allow(clippy::unnecessary_wraps)]
pub fn derive_key_pair(kem: Kem, ikm: &[u8]) -> Res<(PrivateKey, PublicKey)> {
    let (sk, pk) = match kem {
        Kem::X25519Sha256 => {
            let (sk, pk) = X25519HkdfSha256::derive_keypair(ikm);
            (PrivateKey::X25519(sk), PublicKey::X25519(pk))
        }
    };
    trace!("Derived key pair: sk={sk:?} pk={pk:?}");
    Ok((sk, pk))
}

#[cfg(test)]
mod test {
    use super::{
        generate_key_pair, AuthHpkeR, AuthHpkeS, Config, HpkeR, HpkeS, PrivateKey, PublicKey,
    };
    use crate::{
        crypto::{Decrypt, Encrypt},
        hpke::{Aead, Kdf, Kem},
        init,
    };
    use ::hpke::{
        aead::AesGcm256,
        kdf::HkdfSha256,
        kem::{Kem as KemTrait, X25519HkdfSha256},
        setup_sender, Deserializable, OpModeS, Serializable,
    };

    const INFO: &[u8] = b"info";
    const AAD: &[u8] = b"aad";
    const PT: &[u8] = b"message";

    #[allow(clippy::similar_names)] // for sk_x and pk_x
    #[test]
    fn make() {
        init();
        let cfg = Config::default();
        let (sk_r, pk_r) = generate_key_pair(cfg.kem()).unwrap();
        let hpke_s = HpkeS::new(cfg, &pk_r, INFO).unwrap();
        let _hpke_r = HpkeR::new(cfg, &pk_r, &sk_r, &hpke_s.enc().unwrap(), INFO).unwrap();
    }

    #[allow(clippy::similar_names)] // for sk_x and pk_x
    fn seal_open(aead: Aead, kem: Kem) {
        // Setup
        init();
        let cfg = Config {
            kem,
            aead,
            ..Config::default()
        };
        assert!(cfg.supported());
        let (sk_r, pk_r) = generate_key_pair(cfg.kem()).unwrap();

        // Send
        let mut hpke_s = HpkeS::new(cfg, &pk_r, INFO).unwrap();
        let enc = hpke_s.enc().unwrap();
        let ct = hpke_s.seal(AAD, PT).unwrap();

        // Receive
        let mut hpke_r = HpkeR::new(cfg, &pk_r, &sk_r, &enc, INFO).unwrap();
        let pt = hpke_r.open(AAD, &ct).unwrap();
        assert_eq!(&pt[..], PT);
    }

    #[test]
    fn seal_open_gcm() {
        seal_open(Aead::Aes128Gcm, Kem::X25519Sha256);
    }

    #[test]
    fn seal_open_gcm256() {
        seal_open(Aead::Aes256Gcm, Kem::X25519Sha256);
    }

    #[test]
    fn seal_open_chacha() {
        seal_open(Aead::ChaCha20Poly1305, Kem::X25519Sha256);
    }

    // ── Auth mode tests ──

    #[allow(clippy::similar_names)]
    #[test]
    fn auth_make() {
        init();
        let cfg = Config::default();
        let (sk_r, pk_r) = generate_key_pair(cfg.kem()).unwrap();
        let (sk_s, pk_s) = generate_key_pair(cfg.kem()).unwrap();
        let hpke_s = AuthHpkeS::new(cfg, &pk_r, &sk_s, INFO).unwrap();
        let _hpke_r =
            AuthHpkeR::new(cfg, &pk_r, &sk_r, &pk_s, &hpke_s.enc().unwrap(), INFO).unwrap();
    }

    #[allow(clippy::similar_names)]
    fn auth_seal_open(aead: Aead, kem: Kem) {
        init();
        let cfg = Config {
            kem,
            aead,
            ..Config::default()
        };
        assert!(cfg.supported());
        let (sk_r, pk_r) = generate_key_pair(cfg.kem()).unwrap();
        let (sk_s, pk_s) = generate_key_pair(cfg.kem()).unwrap();

        let mut hpke_s = AuthHpkeS::new(cfg, &pk_r, &sk_s, INFO).unwrap();
        let enc = hpke_s.enc().unwrap();
        let ct = hpke_s.seal(AAD, PT).unwrap();

        let mut hpke_r = AuthHpkeR::new(cfg, &pk_r, &sk_r, &pk_s, &enc, INFO).unwrap();
        let pt = hpke_r.open(AAD, &ct).unwrap();
        assert_eq!(&pt[..], PT);
    }

    #[test]
    fn auth_seal_open_gcm() {
        auth_seal_open(Aead::Aes128Gcm, Kem::X25519Sha256);
    }

    #[test]
    fn auth_seal_open_gcm256() {
        auth_seal_open(Aead::Aes256Gcm, Kem::X25519Sha256);
    }

    #[test]
    fn auth_seal_open_chacha() {
        auth_seal_open(Aead::ChaCha20Poly1305, Kem::X25519Sha256);
    }

    // AES-256-GCM known-answer tests.
    //
    // RFC 9180 Appendix A has no AES-256-GCM entry, so these come from the
    // official HPKE interop vectors (cfrg/hpke `test-vectors-5f503c5.json`),
    // entries with kem_id=32, kdf_id=1 and aead_id=2 in Base and Auth mode.
    // Only the fields the tests assert are vendored.

    fn unhex(s: &str) -> Vec<u8> {
        hex::decode(s).expect("valid hex")
    }

    /// A csprng that hands out a fixed byte string.  `setup_sender` draws the
    /// ephemeral keying material once, so feeding it the vector's `ikmE`
    /// reproduces the vector's `enc`.
    struct FixedRng {
        bytes: Vec<u8>,
        pos: usize,
    }

    impl FixedRng {
        fn new(hex_str: &str) -> Self {
            Self {
                bytes: unhex(hex_str),
                pos: 0,
            }
        }
    }

    impl ::hpke::rand_core::RngCore for FixedRng {
        fn next_u32(&mut self) -> u32 {
            let mut b = [0u8; 4];
            self.fill_bytes(&mut b);
            u32::from_le_bytes(b)
        }

        fn next_u64(&mut self) -> u64 {
            let mut b = [0u8; 8];
            self.fill_bytes(&mut b);
            u64::from_le_bytes(b)
        }

        fn fill_bytes(&mut self, dest: &mut [u8]) {
            for d in dest {
                *d = self.bytes[self.pos % self.bytes.len()];
                self.pos += 1;
            }
        }
    }

    impl ::hpke::rand_core::CryptoRng for FixedRng {}

    const KAT_INFO: &[u8] = b"Ode on a Grecian Urn";
    const KAT_AAD: &[u8] = b"Count-0";
    const KAT_PT: &[u8] = b"Beauty is truth, truth beauty";

    const BASE_IKME: &str = "2cd7c601cefb3d42a62b04b7a9041494c06c7843818e0ce28a8f704ae7ab20f9";
    const BASE_SKRM: &str = "497b4502664cfea5d5af0b39934dac72242a74f8480451e1aee7d6a53320333d";
    const BASE_PKRM: &str = "430f4b9859665145a6b1ba274024487bd66f03a2dd577d7753c68d7d7d00c00c";
    const BASE_ENC: &str = "6c93e09869df3402d7bf231bf540fadd35cd56be14f97178f0954db94b7fc256";
    const BASE_CT: &str = "e5d84cd531cfb583096e7cfa9641bd3079cf3a91cda813c52deb5f512be9931980a41de125a925cdad859d5b7a";

    const AUTH_IKME: &str = "734369ab3061f71ee85e090fae308553cac8e7b3fbd45b4ba83d05e0cd05b1c4";
    const AUTH_SKRM: &str = "47f1eee3670dfaaf27c30a83d06ee9f257af174727c17b35328ef730dfc1cd81";
    const AUTH_SKSM: &str = "98fdf9b9773578a79d4ba82fbe483c74cc2e3b8d9525d148a18969fd79a74876";
    const AUTH_PKRM: &str = "3668d659cec6f338f4f8dc6da6733118d2a633f186a3c1415c895111a8eb7c7d";
    const AUTH_PKSM: &str = "4a91c3d0893433f5e31a79fc520f885527a1bc60bf2b0c72693dd7f0b2e41a5a";
    const AUTH_ENC: &str = "9e59f4b1fa5c876f684765290c34e51145894cc4f244342b9fb1a4bdfd8bb426";
    const AUTH_CT: &str = "10b964283ac2cc0bdc4c85ab617291b446bf3832e9359b2c3a0facc50ea75a3c1afd08aeaacd6041d02eb560ec";

    fn kat_sender(
        mode: &OpModeS<'_, X25519HkdfSha256>,
        pk_r_hex: &str,
        ikm_e: &str,
        enc_hex: &str,
        ct_hex: &str,
    ) {
        init();
        let pk_r = <X25519HkdfSha256 as KemTrait>::PublicKey::from_bytes(&unhex(pk_r_hex)).unwrap();
        let (enc, mut ctx) = setup_sender::<AesGcm256, HkdfSha256, X25519HkdfSha256, _>(
            mode,
            &pk_r,
            KAT_INFO,
            &mut FixedRng::new(ikm_e),
        )
        .unwrap();
        assert_eq!(enc.to_bytes().as_slice(), unhex(enc_hex));

        let mut buf = KAT_PT.to_vec();
        let tag = ctx.seal_in_place_detached(&mut buf, KAT_AAD).unwrap();
        buf.extend_from_slice(tag.to_bytes().as_slice());
        assert_eq!(buf, unhex(ct_hex));
    }

    #[test]
    fn kat_base_aes256_sender() {
        kat_sender(&OpModeS::Base, BASE_PKRM, BASE_IKME, BASE_ENC, BASE_CT);
    }

    #[test]
    fn kat_auth_aes256_sender() {
        let sk_s =
            <X25519HkdfSha256 as KemTrait>::PrivateKey::from_bytes(&unhex(AUTH_SKSM)).unwrap();
        let pk_s =
            <X25519HkdfSha256 as KemTrait>::PublicKey::from_bytes(&unhex(AUTH_PKSM)).unwrap();
        kat_sender(
            &OpModeS::Auth((sk_s, pk_s)),
            AUTH_PKRM,
            AUTH_IKME,
            AUTH_ENC,
            AUTH_CT,
        );
    }

    fn aes256_config() -> Config {
        Config {
            kem: Kem::X25519Sha256,
            kdf: Kdf::HkdfSha256,
            aead: Aead::Aes256Gcm,
        }
    }

    #[test]
    fn kat_base_aes256_receiver() {
        init();
        let pk_r = PublicKey::from_x25519_bytes(&unhex(BASE_PKRM)).unwrap();
        let sk_r = PrivateKey::from_x25519_bytes(&unhex(BASE_SKRM)).unwrap();
        let mut hpke_r =
            HpkeR::new(aes256_config(), &pk_r, &sk_r, &unhex(BASE_ENC), KAT_INFO).unwrap();
        let pt = hpke_r.open(KAT_AAD, &unhex(BASE_CT)).unwrap();
        assert_eq!(pt, KAT_PT);
    }

    #[test]
    fn kat_auth_aes256_receiver() {
        init();
        let pk_r = PublicKey::from_x25519_bytes(&unhex(AUTH_PKRM)).unwrap();
        let sk_r = PrivateKey::from_x25519_bytes(&unhex(AUTH_SKRM)).unwrap();
        let pk_s = PublicKey::from_x25519_bytes(&unhex(AUTH_PKSM)).unwrap();
        let mut hpke_r = AuthHpkeR::new(
            aes256_config(),
            &pk_r,
            &sk_r,
            &pk_s,
            &unhex(AUTH_ENC),
            KAT_INFO,
        )
        .unwrap();
        let pt = hpke_r.open(KAT_AAD, &unhex(AUTH_CT)).unwrap();
        assert_eq!(pt, KAT_PT);
    }
}
