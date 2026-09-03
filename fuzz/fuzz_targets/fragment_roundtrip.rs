#![no_main]
//! Layer 2: `split_message` must be exactly undone by `Reassembler`.
//!
//! Structure-aware: instead of random bytes we build real messages of
//! interesting sizes (around `MAX_FRAGMENT_PAYLOAD`, which is where the
//! splitter's boundary arithmetic lives) and then re-deliver them in
//! arbitrary chunks.

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use psrp_rs::fragment::{MAX_FRAGMENT_PAYLOAD, Reassembler, encode_message};

#[derive(Debug, Arbitrary)]
struct Input {
    /// Object ids of the messages to interleave on the wire.
    object_ids: Vec<u32>,
    /// Payload lengths, biased towards the fragment boundary.
    lengths: Vec<u16>,
    /// Delivery chunk size.
    chunk: u16,
    /// Add `MAX_FRAGMENT_PAYLOAD` to every length, to force splitting.
    oversized: bool,
}

fuzz_target!(|input: Input| {
    let count = input.object_ids.len().min(input.lengths.len()).min(8);
    if count == 0 {
        return;
    }

    let mut expected: Vec<Vec<u8>> = Vec::with_capacity(count);
    let mut stream = Vec::new();
    for i in 0..count {
        let mut len = usize::from(input.lengths[i]) % 4096;
        if input.oversized {
            len += MAX_FRAGMENT_PAYLOAD;
        }
        // A recognisable pattern makes a mis-reassembly obvious in the
        // crash artifact instead of "two blobs differ".
        let payload: Vec<u8> = (0..len).map(|b| (b % 251) as u8).collect();
        stream.extend(encode_message(u64::from(input.object_ids[i]), &payload));
        expected.push(payload);
    }

    let chunk = usize::from(input.chunk).max(1);
    let mut reassembler = Reassembler::new();
    let mut got = Vec::new();
    for piece in stream.chunks(chunk) {
        let msgs = reassembler
            .feed(piece)
            .expect("self-encoded fragment stream must reassemble");
        got.extend(msgs);
    }

    assert_eq!(got, expected, "round-trip lost or reordered messages");
    assert!(
        reassembler.is_idle(),
        "reassembler still holds partial state after a complete stream"
    );
});
