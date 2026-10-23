//! Session-key cryptography for MS-PSRP `SecureString` transport.
//!
//! PSRP §3.1.2: to transmit a `SecureString` between the client and
//! server, the two sides negotiate a symmetric session key protected by
//! RSA (RSAES-PKCS1-v1_5).
//!
//! 1. The client generates a 2048-bit RSA keypair.
//! 2. The client sends its public key to the server in a `PublicKey`
//!    message (CLIXML body: a single `<S>` containing the key
//!    serialized as the Windows `BLOBHEADER` + modulus + exponent).
//! 3. The server generates a 256-bit AES session key, encrypts it with
//!    the client's public key (RSAES-PKCS1-v1_5), and sends it back in an
//!    `EncryptedSessionKey` message. Both keys travel base64-encoded
//!    (MS-PSRP 2.2.2.3 and 2.2.2.4).
//! 4. Both sides use that AES key in CBC mode with PKCS#7 padding to
//!    wrap every `<SS>` (SecureString) element. The IV is a fresh
//!    random 16-byte value prefixed to the ciphertext.
//!
//! This module implements the **pure-Rust** crypto (no OpenSSL) needed
//! for that exchange plus a [`SessionKey`] helper that encrypts and
//! decrypts individual `SecureString` values.
//!
//! The exchange itself is driven by the runspace pool — see
//! [`crate::runspace::RunspacePool::request_session_key`].

use aes::Aes256;
use aes::cipher::Array;
use aes::cipher::{BlockCipherDecrypt, BlockCipherEncrypt, KeyInit};
use rand::RngCore;
use rsa::traits::PublicKeyParts;
use rsa::{Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{PsrpError, Result};

/// Header of the `SIMPLEBLOB` that carries the encrypted session key
/// (MS-PSRP 2.2.2.4): `bType` 0x01, `bVersion` 0x02, two reserved bytes,
/// `aiKeyAlg` `CALG_AES_256` (0x6610), then the key-exchange algorithm
/// `CALG_RSA_KEYX` (0xA400), all little-endian.
const SESSION_KEY_BLOB_HEADER: [u8; 12] = [
    0x01, 0x02, 0x00, 0x00, 0x10, 0x66, 0x00, 0x00, 0x00, 0xA4, 0x00, 0x00,
];

/// The only error text for a failed RSA unwrap or a wrong-sized key.
const SESSION_KEY_UNWRAP_FAILED: &str = "session key unwrap failed";

/// Size of the RSA block that follows the header (2048-bit key).
const SESSION_KEY_BLOCK_LEN: usize = 256;

/// Client-side RSA key used for PSRP session-key negotiation.
pub struct ClientSessionKey {
    private: RsaPrivateKey,
}

impl std::fmt::Debug for ClientSessionKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientSessionKey")
            .field("private", &"<redacted>")
            .finish()
    }
}

impl ClientSessionKey {
    /// Generate a fresh 2048-bit RSA keypair.
    pub fn generate() -> Result<Self> {
        let mut rng = rand::thread_rng();
        let private = RsaPrivateKey::new(&mut rng, 2048)
            .map_err(|e| PsrpError::protocol(format!("RSA keygen: {e}")))?;
        Ok(Self { private })
    }

    /// Return the Windows `PUBLICKEYBLOB` representation of the public
    /// key that PSRP expects to transport via the `PublicKey` message.
    ///
    /// The `PublicKey` message carries these bytes base64-encoded
    /// (MS-PSRP 2.2.2.3); [`public_blob_base64`](Self::public_blob_base64)
    /// returns that text.
    ///
    /// Layout — 276 bytes total:
    /// ```text
    /// BLOBHEADER (8 bytes):
    ///   bType    = 0x06    (PUBLICKEYBLOB)   1 byte
    ///   bVersion = 0x02                      1 byte
    ///   reserved = 0x0000                    2 bytes
    ///   aiKeyAlg = 0xa400  (CALG_RSA_KEYX)   4 bytes, little-endian
    /// RSAPUBKEY (12 bytes):
    ///   magic    = "RSA1"                    4 bytes
    ///   bitlen   = 2048                      4 bytes, little-endian
    ///   pubexp   = public exponent           4 bytes, little-endian
    /// modulus (256 bytes, little-endian)
    /// ```
    #[must_use]
    pub fn public_blob(&self) -> Vec<u8> {
        let public = RsaPublicKey::from(&self.private);
        let mut blob = Vec::with_capacity(8 + 12 + 256);
        // BLOBHEADER
        blob.push(0x06);
        blob.push(0x02);
        blob.push(0x00);
        blob.push(0x00);
        blob.extend_from_slice(&0xa400u32.to_le_bytes());
        // RSAPUBKEY
        blob.extend_from_slice(b"RSA1");
        blob.extend_from_slice(&2048u32.to_le_bytes());
        let e_bytes = public.e().to_bytes_le();
        let mut exp = [0u8; 4];
        for (i, b) in e_bytes.iter().take(4).enumerate() {
            exp[i] = *b;
        }
        blob.extend_from_slice(&exp);
        // Force modulus to exactly 256 bytes (little-endian).
        let mut modulus = public.n().to_bytes_le();
        if modulus.len() > 256 {
            modulus.truncate(256);
        } else {
            modulus.resize(256, 0);
        }
        blob.extend_from_slice(&modulus);
        blob
    }

    /// The `PUBLICKEYBLOB` of [`public_blob`](Self::public_blob), base64
    /// encoded: the text MS-PSRP 2.2.2.3 puts in the `PublicKey` property
    /// of the `PUBLIC_KEY` message.
    #[must_use]
    pub fn public_blob_base64(&self) -> String {
        crate::clixml::encode::base64_encode(&self.public_blob())
    }

    /// The `PUBLICKEYBLOB` as upper-case hexadecimal.
    ///
    /// Servers reject this form: MS-PSRP 2.2.2.3 specifies base64 (a real
    /// pwsh 7 answers `Invalid public key data.`).
    #[deprecated(
        since = "3.0.0",
        note = "MS-PSRP sends the key as base64: use `public_blob_base64`"
    )]
    #[must_use]
    pub fn public_blob_hex(&self) -> String {
        use std::fmt::Write as _;
        let blob = self.public_blob();
        let mut hex = String::with_capacity(blob.len() * 2);
        for b in &blob {
            let _ = write!(hex, "{b:02X}");
        }
        hex
    }

    /// Unwrap the `SIMPLEBLOB` of an `ENCRYPTED_SESSION_KEY` message and
    /// return the raw 32-byte AES key.
    ///
    /// `blob` is the base64-decoded property (MS-PSRP 2.2.2.4): the 12-byte
    /// header, then the 256-bit AES key encrypted with the public key of
    /// the `PUBLIC_KEY` message using RSAES-PKCS1-v1_5 (RFC 8017 7.2).
    /// CryptoAPI writes that ciphertext little-endian, so it is reversed
    /// before decryption.
    pub fn decrypt_session_key(&self, blob: &[u8]) -> Result<[u8; 32]> {
        let ciphertext = blob
            .strip_prefix(&SESSION_KEY_BLOB_HEADER)
            .ok_or_else(|| PsrpError::protocol("session key: bad SIMPLEBLOB header"))?;
        if ciphertext.len() != SESSION_KEY_BLOCK_LEN {
            return Err(PsrpError::protocol(format!(
                "session key: expected {SESSION_KEY_BLOCK_LEN} encrypted bytes, got {}",
                ciphertext.len()
            )));
        }
        let mut big_endian = ciphertext.to_vec();
        big_endian.reverse();
        let mut decrypted = self
            .private
            .decrypt_blinded(&mut rand::thread_rng(), Pkcs1v15Encrypt, &big_endian)
            // One fixed message for every post-RSA failure: a bad padding
            // and a wrong plaintext length must not be told apart (the
            // Bleichenbacher oracle), so neither the cause nor the length
            // is reported.
            .map_err(|_| PsrpError::protocol(SESSION_KEY_UNWRAP_FAILED))?;
        if decrypted.len() != 32 {
            decrypted.zeroize();
            return Err(PsrpError::protocol(SESSION_KEY_UNWRAP_FAILED));
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&decrypted);
        decrypted.zeroize();
        Ok(out)
    }
}

/// A negotiated AES-256-CBC session key ready for `SecureString`
/// encryption / decryption.
///
/// Key bytes are zeroized when the value is dropped.
#[derive(Clone, ZeroizeOnDrop)]
pub struct SessionKey {
    key: [u8; 32],
}

impl std::fmt::Debug for SessionKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionKey")
            .field("key", &"<redacted>")
            .finish()
    }
}

impl SessionKey {
    /// Wrap a raw 256-bit key.
    #[must_use]
    pub fn from_bytes(key: [u8; 32]) -> Self {
        Self { key }
    }

    /// Generate a fresh random 256-bit key (server-side test helper).
    #[must_use]
    pub fn random() -> Self {
        let mut key = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut key);
        Self { key }
    }

    /// Encrypt a plaintext string and return `IV || ciphertext`.
    ///
    /// PSRP transports `SecureString` values by UTF-16LE-encoding the
    /// plaintext, AES-CBC encrypting with PKCS#7 padding, and prefixing
    /// the 16-byte IV.
    pub fn encrypt_secure_string(&self, plaintext: &str) -> Vec<u8> {
        // UTF-16LE encode + PKCS#7 pad to 16 bytes.
        let mut padded: Vec<u8> = plaintext
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        let pad = 16 - (padded.len() % 16);
        padded.extend(std::iter::repeat_n(pad as u8, pad));

        let mut iv = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut iv);
        let cipher = Aes256::new(&Array::from(self.key));

        // CBC: for each block, XOR with previous ciphertext (or IV for
        // the first block) then encrypt.
        let mut out = Vec::with_capacity(16 + padded.len());
        out.extend_from_slice(&iv);
        let mut prev: [u8; 16] = iv;
        for chunk in padded.as_chunks::<16>().0 {
            let mut block = [0u8; 16];
            for i in 0..16 {
                block[i] = chunk[i] ^ prev[i];
            }
            let mut ga = Array::from(block);
            cipher.encrypt_block(&mut ga);
            prev.copy_from_slice(ga.as_ref());
            out.extend_from_slice(&prev);
        }
        out
    }

    /// Decrypt `IV || ciphertext` back into the plaintext string.
    pub fn decrypt_secure_string(&self, payload: &[u8]) -> Result<String> {
        if payload.len() < 32 || (payload.len() - 16) % 16 != 0 {
            return Err(PsrpError::protocol("secure string payload malformed"));
        }
        let (iv, ct) = payload.split_at(16);
        let cipher = Aes256::new(&Array::from(self.key));

        let mut prev: [u8; 16] = iv.try_into().unwrap();
        let mut pt = Vec::with_capacity(ct.len());
        for chunk in ct.as_chunks::<16>().0 {
            let mut ga = Array::from(*chunk);
            cipher.decrypt_block(&mut ga);
            let mut block = [0u8; 16];
            for i in 0..16 {
                block[i] = ga[i] ^ prev[i];
            }
            pt.extend_from_slice(&block);
            prev.copy_from_slice(chunk);
        }

        // Strip PKCS#7 padding.
        let pad = *pt
            .last()
            .ok_or_else(|| PsrpError::protocol("empty plaintext"))? as usize;
        if pad == 0 || pad > 16 || pad > pt.len() {
            return Err(PsrpError::protocol("invalid PKCS#7 padding"));
        }
        for &b in &pt[pt.len() - pad..] {
            if b as usize != pad {
                return Err(PsrpError::protocol("invalid PKCS#7 padding"));
            }
        }
        pt.truncate(pt.len() - pad);

        if pt.len() % 2 != 0 {
            return Err(PsrpError::protocol(
                "secure string plaintext not UTF-16 aligned",
            ));
        }
        let units: Vec<u16> = pt
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| u16::from_le_bytes(*c))
            .collect();
        String::from_utf16(&units)
            .map_err(|e| PsrpError::protocol(format!("secure string UTF-16: {e}")))
    }
}

/// What a PSRP server does with a `PUBLIC_KEY` message, for the tests.
#[cfg(test)]
pub(crate) mod test_support {
    use rsa::{BigUint, Pkcs1v15Encrypt, RsaPublicKey};

    use super::SESSION_KEY_BLOB_HEADER;

    /// Wrap `key` for the client whose `PUBLICKEYBLOB` is `public_blob`, as
    /// the server's `ENCRYPTED_SESSION_KEY` carries it (MS-PSRP 2.2.2.4):
    /// the 12-byte `SIMPLEBLOB` header, then the RSAES-PKCS1-v1_5
    /// ciphertext in CryptoAPI's little-endian order.
    pub(crate) fn server_wrap_raw(public_blob: &[u8], key: &[u8]) -> Vec<u8> {
        assert_eq!(public_blob.len(), 8 + 12 + 256, "not a PUBLICKEYBLOB");
        let e = u32::from_le_bytes(public_blob[16..20].try_into().unwrap());
        let n = BigUint::from_bytes_le(&public_blob[20..]);
        let public = RsaPublicKey::new(n, BigUint::from(e)).unwrap();
        let mut ct = public
            .encrypt(&mut rand::thread_rng(), Pkcs1v15Encrypt, key)
            .unwrap();
        ct.reverse();
        let mut out = SESSION_KEY_BLOB_HEADER.to_vec();
        out.extend_from_slice(&ct);
        out
    }

    /// [`server_wrap_raw`] for a 256-bit AES session key.
    pub(crate) fn server_wrap_session_key(public_blob: &[u8], key: &[u8; 32]) -> Vec<u8> {
        server_wrap_raw(public_blob, key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_key_roundtrip_ascii() {
        let key = SessionKey::random();
        let ct = key.encrypt_secure_string("hello world");
        assert!(ct.len() > 16);
        let pt = key.decrypt_secure_string(&ct).unwrap();
        assert_eq!(pt, "hello world");
    }

    #[test]
    fn session_key_roundtrip_unicode() {
        let key = SessionKey::random();
        let ct = key.encrypt_secure_string("héllo 🌍");
        let pt = key.decrypt_secure_string(&ct).unwrap();
        assert_eq!(pt, "héllo 🌍");
    }

    #[test]
    fn session_key_empty_string() {
        let key = SessionKey::random();
        let ct = key.encrypt_secure_string("");
        let pt = key.decrypt_secure_string(&ct).unwrap();
        assert_eq!(pt, "");
    }

    #[test]
    fn decrypt_too_short() {
        let key = SessionKey::random();
        assert!(key.decrypt_secure_string(&[0u8; 4]).is_err());
    }

    #[test]
    fn wrong_key_fails_decrypt() {
        let k1 = SessionKey::random();
        let k2 = SessionKey::random();
        let ct = k1.encrypt_secure_string("x");
        assert!(k2.decrypt_secure_string(&ct).is_err());
    }

    #[test]
    fn session_key_from_bytes() {
        let key = SessionKey::from_bytes([0u8; 32]);
        let ct = key.encrypt_secure_string("abc");
        let pt = SessionKey::from_bytes([0u8; 32])
            .decrypt_secure_string(&ct)
            .unwrap();
        assert_eq!(pt, "abc");
    }

    #[test]
    fn client_session_key_generates_blob() {
        // RSA keygen is slow (~500 ms on modest hardware). Keep to one test.
        let k = ClientSessionKey::generate().unwrap();
        let b64 = k.public_blob_base64();
        // MS-PSRP 2.2.2.3: the PUBLICKEYBLOB travels as base64, never hex.
        assert_eq!(b64, crate::clixml::encode::base64_encode(&k.public_blob()));
        let blob = crate::clixml::encode::base64_decode(&b64).expect("valid base64");
        assert_eq!(blob.len(), 8 + 12 + 256);
        // BLOBHEADER, "RSA1", bitlen 2048 -- the bytes of the spec example
        // (`BgIAAACkAABSU0ExAAgAAAEAAQ...`).
        assert_eq!(
            &blob[..20],
            &[
                0x06, 0x02, 0x00, 0x00, 0x00, 0xA4, 0x00, 0x00, b'R', b'S', b'A', b'1', 0x00, 0x08,
                0x00, 0x00, 0x01, 0x00, 0x01, 0x00
            ]
        );
        assert!(b64.starts_with("BgIAAACkAABSU0ExAAgAAAEAAQ"), "{b64}");
        // The modulus is the key's own, little-endian.
        let public = RsaPublicKey::from(&k.private);
        let mut n = public.n().to_bytes_le();
        n.resize(256, 0);
        assert_eq!(&blob[20..], n.as_slice());
    }

    #[test]
    fn decrypt_misaligned_payload() {
        let key = SessionKey::random();
        // 16 (IV) + 17 (not a multiple of 16)
        let bad = vec![0u8; 33];
        assert!(key.decrypt_secure_string(&bad).is_err());
    }

    #[test]
    fn decrypt_bad_pkcs7_padding() {
        let key = SessionKey::random();
        // Encrypt something valid, then tamper with the last byte (padding)
        let ct = key.encrypt_secure_string("x");
        let mut tampered = ct.clone();
        let len = tampered.len();
        tampered[len - 1] ^= 0xFF; // flip last byte
        assert!(key.decrypt_secure_string(&tampered).is_err());
    }

    #[test]
    fn full_rsa_aes_roundtrip() {
        // Local simulation of the server (MS-PSRP 2.2.2.4): it reads the
        // client's PUBLICKEYBLOB, wraps a random AES key in a SIMPLEBLOB,
        // and the client unwraps it.
        let client = ClientSessionKey::generate().unwrap();
        let aes = {
            let mut k = [0u8; 32];
            rand::thread_rng().fill_bytes(&mut k);
            k
        };
        let blob = test_support::server_wrap_session_key(&client.public_blob(), &aes);
        assert_eq!(blob.len(), 12 + 256, "SIMPLEBLOB is header + RSA block");
        let unwrapped = client.decrypt_session_key(&blob).unwrap();
        assert_eq!(unwrapped, aes);
        let sk = SessionKey::from_bytes(unwrapped);
        let ct = sk.encrypt_secure_string("s3cret");
        let pt = sk.decrypt_secure_string(&ct).unwrap();
        assert_eq!(pt, "s3cret");
    }

    #[test]
    fn decrypt_session_key_rejects_malformed_simpleblob() {
        let client = ClientSessionKey::generate().unwrap();
        let aes = [0x5Au8; 32];
        let good = test_support::server_wrap_session_key(&client.public_blob(), &aes);
        assert_eq!(client.decrypt_session_key(&good).unwrap(), aes);

        // Too short, empty, and a bare RSA block without the header.
        assert!(client.decrypt_session_key(&[]).is_err());
        assert!(client.decrypt_session_key(&good[..11]).is_err());
        assert!(client.decrypt_session_key(&good[12..]).is_err());
        // Truncated and over-long ciphertext.
        assert!(client.decrypt_session_key(&good[..good.len() - 1]).is_err());
        let mut long = good.clone();
        long.push(0);
        assert!(client.decrypt_session_key(&long).is_err());
        // Each header byte is fixed by the spec table.
        for i in 0..12 {
            let mut bad = good.clone();
            bad[i] ^= 0x01;
            assert!(
                client.decrypt_session_key(&bad).is_err(),
                "header byte {i} not checked"
            );
        }
        // Ciphertext in the wrong byte order does not unwrap.
        let mut swapped = good.clone();
        swapped[12..].reverse();
        assert!(client.decrypt_session_key(&swapped).is_err());
        // A key of the wrong size is refused even if the padding is valid.
        let short = test_support::server_wrap_raw(&client.public_blob(), &[1u8; 16]);
        let wrong_len = client.decrypt_session_key(&short).unwrap_err().to_string();
        // A padding failure (wrong byte order) and a wrong plaintext length
        // must be indistinguishable: no Bleichenbacher-style oracle.
        let bad_padding = client
            .decrypt_session_key(&swapped)
            .unwrap_err()
            .to_string();
        assert_eq!(wrong_len, bad_padding, "unwrap failures must be uniform");
        assert!(!wrong_len.contains("16"), "length leaked: {wrong_len}");
    }

    #[test]
    fn client_session_key_debug_redacts_private() {
        let key = ClientSessionKey::generate().unwrap();
        let dbg = format!("{key:?}");
        assert!(dbg.contains("<redacted>"));
        assert!(!dbg.contains("BEGIN"));
    }
}
