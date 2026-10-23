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

/// A second, deliberately different reading of `Convert.FromBase64String`
/// (SP/TAB/CR/LF skipped, groups of four, `=` only closing the last group):
/// the decoder under test must accept exactly what this accepts, and give
/// the same bytes.
fn reference_decode(text: &str) -> Option<Vec<u8>> {
    let symbols: Vec<char> = text
        .chars()
        .filter(|c| !matches!(c, ' ' | '\t' | '\r' | '\n'))
        .collect();
    if symbols.len() % 4 != 0 {
        return None;
    }
    let alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let value = |c: char| alphabet.find(c).map(|i| i as u32);
    let mut out = Vec::new();
    let groups: Vec<&[char]> = symbols.chunks(4).collect();
    for (i, g) in groups.iter().enumerate() {
        let last = i + 1 == groups.len();
        let pad = g.iter().filter(|&&c| c == '=').count();
        // `=` may only close the last group, and only as its tail.
        if pad > 2 || (pad > 0 && !last) || g[..4 - pad].contains(&'=') {
            return None;
        }
        let mut n = 0u32;
        for &c in &g[..4 - pad] {
            n = (n << 6) | value(c)?;
        }
        n <<= 6 * pad as u32;
        let bytes = [(n >> 16) as u8, (n >> 8) as u8, n as u8];
        out.extend_from_slice(&bytes[..3 - pad]);
    }
    Some(out)
}

fuzz_target!(|input: Input| {
    // 0. Same verdict and same bytes as the reference reading of .NET.
    assert_eq!(
        base64::decode(&input.text),
        reference_decode(&input.text),
        "base64 decode disagrees with the reference for {:?}",
        input.text
    );

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
