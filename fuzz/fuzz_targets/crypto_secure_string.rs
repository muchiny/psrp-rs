#![no_main]
//! Layer 4: the PSRP session-key exchange and `SecureString` transport.
//!
//! Both halves take bytes the *server* produced:
//!
//! * `decrypt_session_key` unwraps the SIMPLEBLOB (header + RSAES-PKCS1-v1_5
//!   block) carried by an `EncryptedSessionKey` message;
//! * `decrypt_secure_string` parses an `IV || ciphertext` payload.
//!
//! Neither may panic, read out of bounds, or accept something it should
//! not. The encrypt→decrypt direction has to be exact for every string.

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use psrp_rs::crypto::{ClientSessionKey, SessionKey};

#[derive(Debug, Arbitrary)]
struct Input {
    key: [u8; 32],
    /// Server-supplied `SecureString` blob, decrypted with `key`.
    payload: Vec<u8>,
    /// Plaintext for the encrypt→decrypt direction.
    plaintext: String,
    /// A second key, to confirm cross-key decryption is not accidentally
    /// accepted as valid UTF-16.
    other_key: [u8; 32],
    /// Server-supplied SIMPLEBLOB, unwrapped with the shared client key
    /// below.
    wrapped_session_key: Vec<u8>,
    /// Put a valid SIMPLEBLOB header and a 256-byte block around
    /// `wrapped_session_key`, so the RSA unwrap itself is reached (random
    /// bytes almost never carry the 12-byte header).
    framed: bool,
}

/// MS-PSRP 2.2.2.4 `SIMPLEBLOB` header: `CALG_AES_256` wrapped by `CALG_RSA_KEYX`.
const SIMPLEBLOB_HEADER: [u8; 12] = [
    0x01, 0x02, 0x00, 0x00, 0x10, 0x66, 0x00, 0x00, 0x00, 0xA4, 0x00, 0x00,
];

/// One 2048-bit RSA key pair for the whole process.
///
/// Key generation costs ~100 ms, which would swamp the fuzzing budget if
/// it ran per iteration — and the key is irrelevant to the property under
/// test: `decrypt_session_key` has to reject a malformed blob whatever
/// the key is.
fn client_key() -> &'static ClientSessionKey {
    use std::sync::OnceLock;
    static KEY: OnceLock<ClientSessionKey> = OnceLock::new();
    KEY.get_or_init(|| ClientSessionKey::generate().expect("RSA keygen"))
}

// Generate the RSA key once, in `LLVMFuzzerInitialize`, so its ~100 ms
// (much worse under ASan) lands outside the per-input timer instead of
// being charged to the very first test case as a timeout.
fuzz_target!(init: { client_key(); }, |input: Input| {
    let key = SessionKey::from_bytes(input.key);

    // 1. Hostile `SecureString` payload: any outcome is fine except a panic.
    let _ = key.decrypt_secure_string(&input.payload);

    // 2. Our own ciphertext must decrypt back to exactly the input.
    let sealed = key.encrypt_secure_string(&input.plaintext);
    assert!(
        sealed.len() >= 32 && (sealed.len() - 16) % 16 == 0,
        "encrypt produced a malformed blob of {} bytes",
        sealed.len()
    );
    let opened = key
        .decrypt_secure_string(&sealed)
        .expect("our own ciphertext must decrypt");
    assert_eq!(
        opened, input.plaintext,
        "SecureString round-trip changed the plaintext"
    );

    // 3. The wrong key must not yield the right plaintext.
    if input.other_key != input.key {
        let other = SessionKey::from_bytes(input.other_key);
        if let Ok(bogus) = other.decrypt_secure_string(&sealed) {
            assert_ne!(
                bogus, input.plaintext,
                "decryption succeeded with the wrong session key"
            );
        }
    }

    // 4. Hostile `EncryptedSessionKey` blob. A forged one must never be
    //    unwrapped into a usable key: the header or the PKCS#1 v1.5 padding
    //    check should reject it, and even if they did not, the length
    //    check must.
    let blob = if input.framed {
        let mut block = input.wrapped_session_key.clone();
        block.resize(256, 0);
        [SIMPLEBLOB_HEADER.as_slice(), &block].concat()
    } else {
        input.wrapped_session_key.clone()
    };
    if let Ok(unwrapped) = client_key().decrypt_session_key(&blob) {
        assert_eq!(
            unwrapped.len(),
            32,
            "decrypt_session_key returned a key of the wrong size"
        );
    }

    // The public blob is what the server keys off; it must stay a
    // well-formed Windows PUBLICKEYBLOB whatever else happened, and its
    // base64 form (MS-PSRP 2.2.2.3) must carry exactly those bytes.
    let key = client_key();
    let blob = key.public_blob();
    // 8-byte BLOBHEADER + 12-byte RSAPUBKEY + 256-byte modulus.
    assert_eq!(blob.len(), 8 + 12 + 256, "PUBLICKEYBLOB wrong size");
    assert_eq!(&blob[..2], &[0x06, 0x02], "bad BLOBHEADER");
    assert_eq!(
        psrp_rs::internal::base64::decode(&key.public_blob_base64()),
        Some(blob),
        "PublicKey base64 does not carry the PUBLICKEYBLOB"
    );
});
