#![no_main]
//! Layer 2: fixed-point check over *unrestricted* values.
//!
//! Exact round-tripping is not guaranteed for every `PsValue` (a
//! `<ToString>` is written but not read back, `<D>` is trimmed, and a
//! string that already looks like a `_xHHHH_` escape is ambiguous). What
//! *is* guaranteed is that the codec settles: decoding, re-encoding and
//! decoding again must produce the same value. A codec that keeps
//! mutating a value on every hop corrupts data on a long-lived pipeline.

use libfuzzer_sys::fuzz_target;
use psrp_fuzz::{ArbValue, eq_lossy};
use psrp_rs::clixml::{parse_clixml, to_clixml};

fuzz_target!(|input: ArbValue| {
    let xml = to_clixml(&input.0);
    let Ok(first) = parse_clixml(&xml) else {
        // The encoder can legitimately emit XML the decoder rejects for
        // values that are not representable (e.g. a control character in
        // a position where CLIXML has no escape). That is covered by
        // `clixml_roundtrip`; here we only care about convergence.
        return;
    };
    let Some(first) = first.into_iter().next() else {
        return;
    };

    let xml2 = to_clixml(&first);
    let second = parse_clixml(&xml2).expect("re-encode of a decoded value must parse");
    let second = second.into_iter().next().expect("one value");

    assert!(
        eq_lossy(&first, &second),
        "codec does not reach a fixed point\n  pass 1: {first:?}\n  pass 2: {second:?}\n  xml1: {xml}\n  xml2: {xml2}"
    );
});
