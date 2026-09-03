#![no_main]
//! Layer 1: raw fragment stream from an untrusted server.
//!
//! The reassembler is the very first thing PSRP bytes hit. It must
//! tolerate fragments cut at *any* byte boundary, out-of-order object
//! ids, duplicate `start` flags and truncated headers — and never panic,
//! never loop forever, never grow without bound.

use libfuzzer_sys::fuzz_target;
use psrp_rs::fragment::Reassembler;

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }
    // The first byte picks a chunk size, so a single input covers both
    // "one big write" and "one byte at a time" delivery. Those are
    // genuinely different code paths inside `feed`.
    let chunk = usize::from(data[0]).max(1);
    let body = &data[1..];

    let mut whole = Reassembler::new();
    let whole_result = whole.feed(body);

    let mut chunked = Reassembler::new();
    let mut chunked_messages = Vec::new();
    let mut chunked_failed = false;
    for piece in body.chunks(chunk) {
        match chunked.feed(piece) {
            Ok(msgs) => chunked_messages.extend(msgs),
            Err(_) => {
                chunked_failed = true;
                break;
            }
        }
    }

    // Delivery framing must not change the outcome: the reassembler is
    // supposed to be agnostic to how the bytes were split up.
    if let Ok(whole_messages) = whole_result {
        assert!(
            !chunked_failed,
            "chunked feed failed where a single feed succeeded (chunk={chunk})"
        );
        assert_eq!(
            whole_messages, chunked_messages,
            "reassembly depends on chunking (chunk={chunk})"
        );
        assert_eq!(whole.is_idle(), chunked.is_idle());
    }
});
