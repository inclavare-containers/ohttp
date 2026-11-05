//! Sealed record primitives for carriers that relay an arbitrary byte stream
//! as chunked-ohttp records instead of a bhttp message.
//!
//! Record framing, the maximum chunk size, the per-chunk sequence, the AAD of
//! data and terminating records, and the response key derivation are all
//! decided here. A caller picks record boundaries within [`MAX_CHUNK`] and
//! drives the directions it has; it cannot diverge from the wire format.
//!
//! An error from any `open` method is terminal for the session. The response
//! AEAD consumes a sequence number before it checks the tag, so a failed open
//! desynchronizes the stream permanently; the request-side HPKE receiver does
//! not advance its sequence on failure, but a stream whose framing or
//! authentication failed cannot be recovered either. Carriers must drop the
//! session instead of retrying.

use std::io::Cursor;

use byteorder::{NetworkEndian, ReadBytesExt as _};

use crate::{
    build_info,
    crypto::{Decrypt, Encrypt},
    entropy,
    err::Res,
    export_secret,
    hpke::{Aead as AeadId, Kdf, Kem},
    make_aead, random,
    stream::{
        chunk_read_len, chunk_write_len, AnyReceiverCipher, AnySenderCipher, CHUNK_AAD,
        FINAL_CHUNK_AAD, INFO_REQUEST, LABEL_RESPONSE, MAX_CHUNK_PLAINTEXT,
    },
    Aead, Error, HpkeConfig, HpkeR, HpkeS, KeyConfig, KeyId, Mode, PrivateKey, PublicKey,
    SymmetricSuite, REQUEST_HEADER_LEN,
};
#[cfg(feature = "rust-hpke")]
use crate::{AuthHpkeR, AuthHpkeS};

/// Largest plaintext carried in one record.
pub const MAX_CHUNK: usize = MAX_CHUNK_PLAINTEXT;

/// Seal one data record: the varint ciphertext length followed by the
/// ciphertext AEAD'd under the empty chunk AAD. Same framing as
/// `ChunkWriter::write_chunk` with `last = false`.
fn seal_chunk<C: Encrypt>(cipher: &mut C, plaintext: &[u8]) -> Res<Vec<u8>> {
    // The caller owns the split at `MAX_CHUNK` so each record maps to one
    // transport message; an oversize input is a caller bug, mirroring
    // `ChunkReader`'s `ChunkTooLarge` rejection.
    if plaintext.len() > MAX_CHUNK_PLAINTEXT {
        return Err(Error::ChunkTooLarge);
    }
    let ct = cipher.seal(CHUNK_AAD, plaintext)?;
    let mut len = [0; 8];
    let prefix = chunk_write_len(&mut len, ct.len());
    let mut record = Vec::with_capacity(prefix.len() + ct.len());
    record.extend_from_slice(prefix);
    record.extend_from_slice(&ct);
    Ok(record)
}

/// Seal the terminating record: a zero varint followed by the ciphertext of an
/// empty plaintext under the final-chunk AAD. Matches `write_chunk(.., true)`.
fn seal_final<C: Encrypt>(cipher: &mut C) -> Res<Vec<u8>> {
    let ct = cipher.seal(FINAL_CHUNK_AAD, &[])?;
    let mut len = [0; 8];
    let prefix = chunk_write_len(&mut len, 0);
    let mut record = Vec::with_capacity(prefix.len() + ct.len());
    record.extend_from_slice(prefix);
    record.extend_from_slice(&ct);
    Ok(record)
}

/// Open one whole record the way `ChunkReader` would. `Ok(Some(..))` for a data
/// chunk, `Ok(None)` once the final chunk is verified.
fn open_chunk<C: Decrypt>(cipher: &mut C, record: &[u8]) -> Res<Option<Vec<u8>>> {
    let (len, prefix) = chunk_read_len(record)?;
    let ct = record.get(prefix..).ok_or(Error::Truncated)?;
    let n_t = cipher.alg().n_t();
    if len == 0 {
        // The final chunk's ciphertext length is implied by the AEAD tag,
        // exactly as `ChunkReader` treats a zero length. Anything else would
        // be silently discarded by the AEAD, so reject it outright.
        if ct.len() != n_t {
            return Err(Error::Truncated);
        }
        cipher.open(FINAL_CHUNK_AAD, ct)?;
        return Ok(None);
    }
    // The peer holds the session key, so an unbounded prefix must not make us
    // decrypt and buffer an arbitrarily large record. This is the same bound
    // `ChunkReader` applies before reading a record's ciphertext.
    if len > MAX_CHUNK_PLAINTEXT + n_t {
        return Err(Error::ChunkTooLarge);
    }
    if ct.len() != len {
        return Err(Error::Truncated);
    }
    Ok(Some(cipher.open(CHUNK_AAD, ct)?))
}

/// The client's record sealer, keyed by the HPKE sender context.
pub struct ClientSealer {
    cipher: AnySenderCipher,
    closed: bool,
}

impl ClientSealer {
    /// Seal one data chunk (at most [`MAX_CHUNK`] bytes; longer inputs are a
    /// caller error, not silently split).
    pub fn seal(&mut self, plaintext: &[u8]) -> Res<Vec<u8>> {
        if self.closed {
            return Err(Error::WriteAfterClose);
        }
        seal_chunk(&mut self.cipher, plaintext)
    }

    /// Seal the terminating chunk of the direction. No later [`Self::seal`] or
    /// [`Self::seal_final`] succeeds; both return [`Error::WriteAfterClose`].
    pub fn seal_final(&mut self) -> Res<Vec<u8>> {
        if self.closed {
            return Err(Error::WriteAfterClose);
        }
        self.closed = true;
        seal_final(&mut self.cipher)
    }
}

/// The client's response opener before the server nonce has been seen. It
/// carries the response exporter secret, `enc`, and config; the actual AEAD
/// keys up in [`PendingClientOpener::with_response_nonce`].
pub struct PendingClientOpener {
    config: HpkeConfig,
    enc: Vec<u8>,
    secret: crate::SymKey,
}

impl PendingClientOpener {
    /// Derive the response opener from the `response_nonce` the server sent.
    pub fn with_response_nonce(self, response_nonce: &[u8]) -> Res<ClientOpener> {
        if response_nonce.len() != entropy(self.config) {
            return Err(Error::Truncated);
        }
        let cipher = make_aead(
            Mode::Decrypt,
            self.config,
            &self.secret,
            &self.enc,
            response_nonce,
        )?;
        Ok(ClientOpener {
            cipher,
            done: false,
        })
    }
}

/// The client's response opener, derived from the server's response nonce.
pub struct ClientOpener {
    cipher: Aead,
    done: bool,
}

impl ClientOpener {
    /// Open one response record. `Ok(None)` after the final chunk; opening
    /// further records past that is a protocol error.
    pub fn open(&mut self, record: &[u8]) -> Res<Option<Vec<u8>>> {
        if self.done {
            return Err(Error::ExtraData);
        }
        let pt = open_chunk(&mut self.cipher, record)?;
        if pt.is_none() {
            self.done = true;
        }
        Ok(pt)
    }
}

/// The server's opener for client records, sharing the receiver context's own
/// sequence counter.
pub struct ServerOpener {
    cipher: AnyReceiverCipher,
    done: bool,
}

impl ServerOpener {
    /// Open one client record. `Ok(None)` after the final chunk; further
    /// records are a protocol error.
    pub fn open(&mut self, record: &[u8]) -> Res<Option<Vec<u8>>> {
        if self.done {
            return Err(Error::ExtraData);
        }
        let pt = open_chunk(&mut self.cipher, record)?;
        if pt.is_none() {
            self.done = true;
        }
        Ok(pt)
    }
}

/// The server's record sealer for the response direction.
pub struct ServerSealer {
    cipher: Aead,
    response_nonce: Vec<u8>,
    closed: bool,
}

impl ServerSealer {
    /// Seal one data chunk (at most [`MAX_CHUNK`] bytes).
    pub fn seal(&mut self, plaintext: &[u8]) -> Res<Vec<u8>> {
        if self.closed {
            return Err(Error::WriteAfterClose);
        }
        seal_chunk(&mut self.cipher, plaintext)
    }

    /// Seal the terminating chunk of the direction. No later [`Self::seal`] or
    /// [`Self::seal_final`] succeeds; both return [`Error::WriteAfterClose`].
    pub fn seal_final(&mut self) -> Res<Vec<u8>> {
        if self.closed {
            return Err(Error::WriteAfterClose);
        }
        self.closed = true;
        seal_final(&mut self.cipher)
    }

    /// The CSPRNG nonce generated with this sealer; send it to the client
    /// unchanged so its pending opener can key the response direction.
    #[must_use]
    pub fn response_nonce(&self) -> &[u8] {
        &self.response_nonce
    }
}

/// Wrap a client sender context into the header bytes and both directions.
///
/// The header is the fixed request info prefix plus `enc`, byte-identical to
/// what the stream path queues as its first bytes.
fn start_with_sender(
    cipher: AnySenderCipher,
    info: &[u8],
) -> Res<(Vec<u8>, ClientSealer, PendingClientOpener)> {
    let mut header = Vec::from(&info[INFO_REQUEST.len() + 1..]);
    debug_assert_eq!(header.len(), REQUEST_HEADER_LEN);
    let config = cipher.config();
    let enc = cipher.enc()?;
    header.extend_from_slice(&enc);
    let secret = export_secret(&cipher, LABEL_RESPONSE, config)?;
    Ok((
        header,
        ClientSealer {
            cipher,
            closed: false,
        },
        PendingClientOpener {
            config,
            enc,
            secret,
        },
    ))
}

#[cfg(feature = "client")]
impl crate::ClientRequest {
    /// Build the request header and both record directions without binding a
    /// body stream. The returned header is byte-identical to the prefix the
    /// streaming [`crate::stream::ClientRequest::start`] writes.
    pub fn start_without_body(
        config: HpkeConfig,
        key_id: KeyId,
        pk: &PublicKey,
    ) -> Res<(Vec<u8>, ClientSealer, PendingClientOpener)> {
        let info = build_info(INFO_REQUEST, key_id, config)?;
        let hpke = HpkeS::new(config, pk, &info)?;
        start_with_sender(AnySenderCipher::Base(hpke), &info)
    }

    /// Auth-mode variant of [`Self::start_without_body`].
    #[cfg(feature = "rust-hpke")]
    pub fn start_without_body_with_client_key(
        config: HpkeConfig,
        key_id: KeyId,
        pk: &PublicKey,
        sk_s: &PrivateKey,
    ) -> Res<(Vec<u8>, ClientSealer, PendingClientOpener)> {
        let info = build_info(INFO_REQUEST, key_id, config)?;
        let hpke = AuthHpkeS::new(config, pk, sk_s, &info)?;
        start_with_sender(AnySenderCipher::Auth(hpke), &info)
    }
}

/// A request header decoded from a whole buffer, before the server key is
/// installed. The key id and symmetric suite are readable immediately;
/// opening the session waits for [`DecodedHeader::into_chunk_parts`].
///
/// # Errors
/// `Error::Truncated` if the header is shorter than the request header or its
/// `enc`, `Error::Format` if it is longer than expected, plus the backend
/// errors for an unsupported KEM identifier.
#[cfg(feature = "server")]
pub struct DecodedHeader {
    key_id: KeyId,
    buf: [u8; REQUEST_HEADER_LEN],
    enc: Vec<u8>,
}

#[cfg(feature = "server")]
impl DecodedHeader {
    /// The key id named by the header, for config lookup before
    /// decapsulation.
    #[must_use]
    pub fn key_id(&self) -> KeyId {
        self.key_id
    }

    /// The symmetric suite carried by the header.
    pub fn symmetric_suite(&self) -> Res<SymmetricSuite> {
        let mut r = Cursor::new(&self.buf[..]);
        r.read_u8()?; // key_id
        Kem::try_from(r.read_u16::<NetworkEndian>()?)?;
        let kdf = Kdf::try_from(r.read_u16::<NetworkEndian>()?)?;
        let aead = AeadId::try_from(r.read_u16::<NetworkEndian>()?)?;
        Ok(SymmetricSuite::new(kdf, aead))
    }

    /// Install the server key and derive both record directions.
    // The key config travels here by value as documented; only its
    // references are read, which clippy would rather pass by reference.
    #[allow(clippy::needless_pass_by_value)]
    pub fn into_chunk_parts(self, key_config: KeyConfig) -> Res<(ServerOpener, ServerSealer)> {
        let config = self.decode_config(&key_config)?;
        let info = build_info(INFO_REQUEST, key_config.key_id, config)?;
        let hpke = HpkeR::new(
            config,
            &key_config.pk,
            server_sk(&key_config)?,
            &self.enc,
            &info,
        )?;
        server_parts(config, AnyReceiverCipher::Base(hpke), &self.enc)
    }

    /// Install the server key in HPKE Auth mode, verifying the sender.
    // Same by-value config contract as `into_chunk_parts`.
    #[allow(clippy::needless_pass_by_value)]
    #[cfg(feature = "rust-hpke")]
    pub fn into_chunk_parts_with_client_pk(
        self,
        key_config: KeyConfig,
        client_pk: PublicKey,
    ) -> Res<(ServerOpener, ServerSealer)> {
        let config = self.decode_config(&key_config)?;
        let info = build_info(INFO_REQUEST, key_config.key_id, config)?;
        let hpke = AuthHpkeR::new(
            config,
            &key_config.pk,
            server_sk(&key_config)?,
            &client_pk,
            &self.enc,
            &info,
        )?;
        server_parts(config, AnyReceiverCipher::Auth(hpke), &self.enc)
    }

    fn decode_config(&self, key_config: &KeyConfig) -> Res<HpkeConfig> {
        // Re-reads key_id/kem from the header and rejects a mismatch with
        // this config, same as `ServerRequest::read_config`.
        let hpke_config = key_config.decode_hpke_config(&mut Cursor::new(&self.buf[..]))?;
        // `decode_hpke_config` accepts any KDF/AEAD id the header names. Only
        // suites this key config actually advertises may key the session,
        // otherwise a client could pick an AEAD the operator never offered.
        key_config.select(SymmetricSuite::new(hpke_config.kdf(), hpke_config.aead()))
    }
}

#[cfg(feature = "server")]
fn server_sk(key_config: &KeyConfig) -> Res<&PrivateKey> {
    // A KeyConfig decoded from the wire carries no private key and cannot
    // open anything; callers must supply the server-side one.
    key_config.sk.as_ref().ok_or(Error::Unsupported)
}

/// Both record directions of a session after the header exchange. The response
/// context is derived here, at construction, exactly as a chunked response
/// encapsulator would: a fresh CSPRNG nonce plus an AEAD keyed from the
/// response exporter secret.
#[cfg(feature = "server")]
fn server_parts(
    config: HpkeConfig,
    c2s: AnyReceiverCipher,
    enc: &[u8],
) -> Res<(ServerOpener, ServerSealer)> {
    let response_nonce = random(entropy(config));
    let secret = export_secret(&c2s, LABEL_RESPONSE, config)?;
    let cipher = make_aead(Mode::Encrypt, config, &secret, enc, &response_nonce)?;
    Ok((
        ServerOpener {
            cipher: c2s,
            done: false,
        },
        ServerSealer {
            cipher,
            response_nonce,
            closed: false,
        },
    ))
}

#[cfg(feature = "server")]
impl crate::Server {
    /// Decode a request header from a whole buffer. This is the synchronous
    /// counterpart of the streaming [`crate::Server::decode_header`].
    ///
    /// # Errors
    /// See [`DecodedHeader`].
    pub fn decode_header_from_slice(header: &[u8]) -> Res<DecodedHeader> {
        if header.len() < REQUEST_HEADER_LEN {
            return Err(Error::Truncated);
        }
        // The `enc` length depends on the KEM named in the header, so the KEM
        // id must be parsed before the rest of the framing can be checked.
        let kem = Kem::try_from(u16::from_be_bytes([header[1], header[2]]))?;
        // Reject invalid suite ids here rather than deferring to key install.
        Kdf::try_from(u16::from_be_bytes([header[3], header[4]]))?;
        AeadId::try_from(u16::from_be_bytes([header[5], header[6]]))?;
        let expected = REQUEST_HEADER_LEN + kem.n_enc();
        if header.len() != expected {
            return Err(if header.len() > expected {
                Error::Format
            } else {
                Error::Truncated
            });
        }
        let mut buf = [0; REQUEST_HEADER_LEN];
        buf.copy_from_slice(&header[..REQUEST_HEADER_LEN]);
        Ok(DecodedHeader {
            key_id: header[0],
            buf,
            enc: header[REQUEST_HEADER_LEN..].to_vec(),
        })
    }
}

#[cfg(test)]
mod test {
    use super::{
        ClientOpener, ClientSealer, PendingClientOpener, ServerOpener, ServerSealer, MAX_CHUNK,
    };
    use crate::{
        hpke::{Aead, Kdf, Kem},
        stream::chunk_write_len,
        test::{init, make_config},
        ClientRequest, Error, HpkeConfig, SymmetricSuite, REQUEST_HEADER_LEN,
    };

    /// A client pending opener, keyed but not yet given the response nonce.
    fn pending_opener() -> PendingClientOpener {
        init();
        let key_config = make_config();
        let config = key_config.select(key_config.symmetric()[0]).unwrap();
        let (_header, _sealer, pending) =
            ClientRequest::start_without_body(config, key_config.key_id(), &key_config.pk).unwrap();
        pending
    }

    /// A fresh client+server pair after the in-stream header exchange. The
    /// header is carried out of band, as a tunnel carrier would.
    fn session() -> (ClientSealer, ClientOpener, ServerOpener, ServerSealer) {
        init();
        let key_config = make_config();
        let config = key_config.select(key_config.symmetric()[0]).unwrap();
        let key_id = key_config.key_id();
        let pk = key_config.pk.clone();
        let (header, c2s_sealer, client_pending) =
            ClientRequest::start_without_body(config, key_id, &pk).unwrap();
        let (c2s_opener, s2c_sealer) = crate::Server::decode_header_from_slice(&header)
            .unwrap()
            .into_chunk_parts(key_config)
            .unwrap();
        let s2c_opener = client_pending
            .with_response_nonce(s2c_sealer.response_nonce())
            .unwrap();
        (c2s_sealer, s2c_opener, c2s_opener, s2c_sealer)
    }

    #[test]
    fn header_matches_request_prefix() {
        init();
        let key_config = make_config();
        let config = key_config.select(key_config.symmetric()[0]).unwrap();
        let key_id = key_config.key_id();
        let pk = key_config.pk.clone();
        let (header, _, _) = ClientRequest::start_without_body(config, key_id, &pk).unwrap();
        // `ClientRequest::start` writes the same info prefix to the stream.
        // The `enc` suffix differs per context (fresh ephemeral key), so only
        // the fixed header prefix can be compared byte for byte.
        let full =
            crate::stream::ClientRequest::start(Vec::<u8>::new(), config, key_id, &pk).unwrap();
        assert_eq!(header.len(), REQUEST_HEADER_LEN + Kem::X25519Sha256.n_enc());
        assert_eq!(header.len(), full.header().len());
        assert_eq!(
            &header[..REQUEST_HEADER_LEN],
            &full.header()[..REQUEST_HEADER_LEN]
        );
        assert_eq!(header[0], key_id);
    }

    #[test]
    fn header_reports_key_id_and_suite() {
        init();
        let key_config = make_config();
        let config = key_config.select(key_config.symmetric()[0]).unwrap();
        let key_id = key_config.key_id();
        let pk = key_config.pk.clone();
        let (header, _, _) = ClientRequest::start_without_body(config, key_id, &pk).unwrap();
        let decoded = crate::Server::decode_header_from_slice(&header).unwrap();
        assert_eq!(decoded.key_id(), key_id);
        assert_eq!(
            decoded.symmetric_suite().unwrap(),
            key_config.symmetric()[0]
        );
    }

    /// C2S bytes seal to a record, the server opens them back, and a final
    /// record ends the stream (open returns None).
    #[test]
    fn roundtrip_c2s_with_final() {
        let (mut c2s, _opener, mut server_c2s, _s2c) = session();
        let record = c2s.seal(b"hello chunk").unwrap();
        assert_eq!(
            server_c2s.open(&record).unwrap().as_deref(),
            Some(&b"hello chunk"[..])
        );

        // A second chunk continues the sequence.
        let record2 = c2s.seal(b"second").unwrap();
        assert_eq!(
            server_c2s.open(&record2).unwrap().as_deref(),
            Some(&b"second"[..])
        );

        // The terminating chunk yields None and closes the direction.
        let final_record = c2s.seal_final().unwrap();
        assert_eq!(server_c2s.open(&final_record).unwrap(), None);
        assert!(server_c2s.open(&final_record).is_err());
    }

    /// S2C bytes seal on the server and open on the client; final ends it.
    #[test]
    fn roundtrip_s2c_with_final() {
        let (_c2s, mut client_s2c, _server_c2s, mut s2c) = session();
        let record = s2c.seal(b"reply").unwrap();
        assert_eq!(
            client_s2c.open(&record).unwrap().as_deref(),
            Some(&b"reply"[..])
        );
        let final_record = s2c.seal_final().unwrap();
        assert_eq!(client_s2c.open(&final_record).unwrap(), None);
    }

    /// A chunk larger than `MAX_CHUNK` cannot be sealed in one record.
    #[test]
    fn seal_rejects_oversize_chunk() {
        let (mut c2s, _opener, _server_c2s, _s2c) = session();
        let big = vec![0u8; MAX_CHUNK + 1];
        assert!(c2s.seal(&big).is_err());
    }

    #[test]
    fn tampered_record_fails() {
        let (mut c2s, _opener, mut server_c2s, _s2c) = session();
        let mut record = c2s.seal(b"data").unwrap();
        // Flip a byte in the ciphertext body (skip the varint length prefix).
        let last = record.len() - 1;
        record[last] ^= 0x01;
        assert!(server_c2s.open(&record).is_err());
    }

    #[test]
    fn directions_are_independent() {
        let (mut c2s, mut client_s2c, mut server_c2s, mut s2c) = session();

        // Interleave the directions; each sequence continues from its own
        // counter regardless of the other's progress.
        let ct1 = c2s.seal(b"one").unwrap();
        let reply1 = s2c.seal(b"reply-1").unwrap();
        assert_eq!(server_c2s.open(&ct1).unwrap().as_deref(), Some(&b"one"[..]));
        assert_eq!(
            client_s2c.open(&reply1).unwrap().as_deref(),
            Some(&b"reply-1"[..])
        );

        let ct2 = c2s.seal(b"two").unwrap();
        let reply2 = s2c.seal(b"reply-2").unwrap();
        assert_eq!(server_c2s.open(&ct2).unwrap().as_deref(), Some(&b"two"[..]));
        assert_eq!(
            client_s2c.open(&reply2).unwrap().as_deref(),
            Some(&b"reply-2"[..])
        );
    }

    #[test]
    fn decode_rejects_bad_header() {
        init();
        let key_config = make_config();
        let config = key_config.select(key_config.symmetric()[0]).unwrap();
        let key_id = key_config.key_id();
        let pk = key_config.pk.clone();
        let (header, _, _) = ClientRequest::start_without_body(config, key_id, &pk).unwrap();

        // Truncated header.
        assert!(
            crate::Server::decode_header_from_slice(&header[..REQUEST_HEADER_LEN - 1]).is_err()
        );
        // Truncated enc.
        assert!(crate::Server::decode_header_from_slice(&header[..=REQUEST_HEADER_LEN]).is_err());
        // Extra trailing bytes.
        let mut long = header.clone();
        long.push(0);
        assert!(crate::Server::decode_header_from_slice(&long).is_err());

        // A key config that doesn't match the header's key id is rejected.
        let decoded = crate::Server::decode_header_from_slice(&header).unwrap();
        let mut other = key_config;
        other.key_id ^= 0xff;
        assert!(decoded.into_chunk_parts(other).is_err());
    }

    #[cfg(feature = "rust-hpke")]
    #[test]
    fn roundtrip_auth_mode() {
        init();
        let key_config = make_config();
        let config = key_config.select(key_config.symmetric()[0]).unwrap();
        let key_id = key_config.key_id();
        let pk = key_config.pk.clone();
        let client_keys = make_config();
        let sk_s = client_keys.dangerous_sk().unwrap();
        let pk_s = client_keys.pk.clone();

        let (header, mut c2s, client_pending) =
            ClientRequest::start_without_body_with_client_key(config, key_id, &pk, sk_s).unwrap();
        let (mut server_c2s, mut s2c) = crate::Server::decode_header_from_slice(&header)
            .unwrap()
            .into_chunk_parts_with_client_pk(key_config, pk_s)
            .unwrap();
        let mut client_s2c = client_pending
            .with_response_nonce(s2c.response_nonce())
            .unwrap();

        let record = c2s.seal(b"auth").unwrap();
        assert_eq!(
            server_c2s.open(&record).unwrap().as_deref(),
            Some(&b"auth"[..])
        );

        let reply = s2c.seal(b"auth-reply").unwrap();
        assert_eq!(
            client_s2c.open(&reply).unwrap().as_deref(),
            Some(&b"auth-reply"[..])
        );
    }

    /// The response nonce must have exactly the suite's nonce length.
    #[test]
    fn rejects_wrong_response_nonce_length() {
        let nonce_len = {
            let key_config = make_config();
            let config = key_config.select(key_config.symmetric()[0]).unwrap();
            crate::entropy(config)
        };
        let short = vec![0u8; nonce_len - 1];
        let long = vec![0u8; nonce_len + 1];
        assert!(pending_opener().with_response_nonce(&short).is_err());
        assert!(pending_opener().with_response_nonce(&long).is_err());
        assert!(pending_opener().with_response_nonce(&[]).is_err());
    }

    /// A client that names a suite the key config does not advertise is
    /// rejected before any decryption happens.
    #[test]
    fn rejects_unadvertised_symmetric_suite() {
        init();
        let key_config = make_config();
        // `make_config` advertises Aes128Gcm and ChaCha20Poly1305, not Aes256Gcm.
        let config = HpkeConfig::new(Kem::X25519Sha256, Kdf::HkdfSha256, Aead::Aes256Gcm);
        let (header, _, _) =
            ClientRequest::start_without_body(config, key_config.key_id(), &key_config.pk).unwrap();
        let decoded = crate::Server::decode_header_from_slice(&header).unwrap();
        assert_eq!(
            decoded.symmetric_suite().unwrap(),
            SymmetricSuite::new(Kdf::HkdfSha256, Aead::Aes256Gcm)
        );
        assert!(matches!(
            decoded.into_chunk_parts(key_config),
            Err(Error::Unsupported)
        ));
    }

    /// The final record is terminal: sealing and finalizing again both fail.
    #[test]
    fn seal_after_final_is_rejected() {
        let (mut c2s, _client_s2c, _server_c2s, mut s2c) = session();

        c2s.seal_final().unwrap();
        assert!(matches!(c2s.seal(b"late"), Err(Error::WriteAfterClose)));
        assert!(matches!(c2s.seal_final(), Err(Error::WriteAfterClose)));

        s2c.seal_final().unwrap();
        assert!(matches!(s2c.seal(b"late"), Err(Error::WriteAfterClose)));
        assert!(matches!(s2c.seal_final(), Err(Error::WriteAfterClose)));
    }

    /// The client's response opener refuses records after the final chunk.
    #[test]
    fn client_open_after_final_is_rejected() {
        let (_c2s, mut client_s2c, _server_c2s, mut s2c) = session();
        let final_record = s2c.seal_final().unwrap();
        assert_eq!(client_s2c.open(&final_record).unwrap(), None);
        assert!(matches!(
            client_s2c.open(&final_record),
            Err(Error::ExtraData)
        ));
    }

    #[test]
    fn tampered_final_record_fails() {
        let (mut c2s, _client_s2c, mut server_c2s, _s2c) = session();
        let mut final_record = c2s.seal_final().unwrap();
        let last = final_record.len() - 1;
        final_record[last] ^= 0x01;
        assert!(server_c2s.open(&final_record).is_err());
    }

    /// A final record's ciphertext is exactly the AEAD tag; trailing bytes are
    /// not silently discarded.
    #[test]
    fn final_record_with_extra_ciphertext_is_rejected() {
        let (mut c2s, _client_s2c, mut server_c2s, _s2c) = session();
        let mut final_record = c2s.seal_final().unwrap();
        final_record.push(0);
        assert!(matches!(
            server_c2s.open(&final_record),
            Err(Error::Truncated)
        ));
    }

    /// The largest legal plaintext fits one record and round-trips.
    #[test]
    fn max_chunk_plaintext_roundtrips() {
        let (mut c2s, _client_s2c, mut server_c2s, _s2c) = session();
        let plaintext = vec![0xa5; MAX_CHUNK];
        let record = c2s.seal(&plaintext).unwrap();
        assert_eq!(
            server_c2s.open(&record).unwrap().as_deref(),
            Some(&plaintext[..])
        );
    }

    /// An inbound length prefix beyond the streaming reader's bound is
    /// rejected before any ciphertext is read.
    #[test]
    fn oversized_inbound_record_is_rejected() {
        let (_c2s, _client_s2c, mut server_c2s, _s2c) = session();
        // `MAX_CHUNK` plaintext plus the tag is the largest legal record.
        let mut buf = [0; 8];
        let record = chunk_write_len(&mut buf, MAX_CHUNK + Aead::Aes128Gcm.n_t() + 1).to_vec();
        assert!(matches!(
            server_c2s.open(&record),
            Err(Error::ChunkTooLarge)
        ));
    }
}
