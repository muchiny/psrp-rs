#![no_main]
//! Layer 4: `SecureString` transport crypto.
//!
//! `decrypt_secure_string` parses an `IV || ciphertext` blob that the
//! *server* produced: it has to reject short, misaligned, badly padded
//! and non-UTF-16 payloads without panicking or reading out of bounds.
//! The encrypt→decrypt direction has to be exact for every string.

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use psrp_rs::crypto::SessionKey;

#[derive(Debug, Arbitrary)]
struct Input {
    key: [u8; 32],
    /// Server-supplied blob, decrypted with `key`.
    payload: Vec<u8>,
    /// Plaintext for the encrypt→decrypt direction.
    plaintext: String,
    /// A second key, to confirm cross-key decryption is not accidentally
    /// accepted as valid UTF-16.
    other_key: [u8; 32],
}

fuzz_target!(|input: Input| {
    let key = SessionKey::from_bytes(input.key);

    // 1. Hostile payload: any outcome is fine except a panic.
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
});
