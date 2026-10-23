#![no_main]
//! Layer 5: the small hand-rolled codecs.
//!
//! `base64_decode` backs CLIXML `<BA>`, the `PublicKey` and
//! `EncryptedSessionKey` messages and the OutOfProc `<Data>` packets: it
//! reads straight from the wire and is hand-written here rather than
//! pulled from a crate, so it deserves its own target.

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use psrp_rs::internal::base64;

#[derive(Debug, Arbitrary)]
struct Input {
    /// Untrusted text fed to the decoder.
    text: String,
    /// Bytes fed through the encoders and back.
    bytes: Vec<u8>,
}

fuzz_target!(|input: Input| {
    // 1. Hostile text: decode must not panic, and must be self-consistent.
    if let Some(decoded) = base64::decode(&input.text) {
        let re = base64::encode(&decoded);
        let again = base64::decode(&re).expect("re-encoded base64 must decode");
        assert_eq!(decoded, again, "base64 decode/encode is not stable");
    }

    // 2. Encoder output must always be accepted back.
    let encoded = base64::encode(&input.bytes);
    assert_eq!(
        base64::decode(&encoded).as_deref(),
        Some(input.bytes.as_slice()),
        "base64 round-trip lost data"
    );
});
