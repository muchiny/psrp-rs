#![no_main]
//! Layer 5: the SSH OutOfProc line codec.
//!
//! The bytes `pwsh -sshs` writes are cut into lines by the line splitter,
//! and every line is parsed as one packet. Both steps see attacker bytes,
//! so three properties are asserted:
//!
//! 1. delivery framing never changes the outcome (one big read or one
//!    byte at a time give the same lines, or the same failure);
//! 2. re-encoding a parsed line is a fixed point;
//! 3. nothing panics and no line exceeds `MAX_LINE_BYTES`.

use libfuzzer_sys::fuzz_target;
use psrp_rs::internal::out_of_proc::{MAX_LINE_BYTES, reencode, split};

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }
    // The first byte picks a chunk size, as in `fragment_reassembler`.
    let chunk = usize::from(data[0]).max(1);
    let body = &data[1..];

    let whole = split(&[body]);
    let chunks: Vec<&[u8]> = body.chunks(chunk).collect();
    let chunked = split(&chunks);

    // Property 1: framing independence (`None` is "the splitter reported
    // an error", which must not depend on the framing either).
    assert_eq!(
        whole, chunked,
        "line splitting depends on chunking (chunk={chunk})"
    );

    let Some(lines) = whole else {
        return;
    };
    for line in &lines {
        // Property 3: the length limit holds for every rendered line.
        assert!(
            line.len() <= MAX_LINE_BYTES,
            "line of {} bytes exceeds MAX_LINE_BYTES",
            line.len()
        );
        // Property 2: whatever parses re-encodes to a fixed point.
        if let Some(encoded) = reencode(line) {
            assert_eq!(
                reencode(&encoded).as_deref(),
                Some(encoded.as_str()),
                "re-encoding is not a fixed point for {line:?}"
            );
        }
    }
});
