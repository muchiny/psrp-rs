#![no_main]
//! Layer 2: strict CLIXML round-trip on the values that are *supposed*
//! to survive it exactly.
//!
//! `SafeValue` is deliberately restricted (see `psrp_fuzz::SafeValue`
//! for the list and the reason behind each restriction), so any failure
//! here is a genuine codec bug rather than a known lossy corner.

use libfuzzer_sys::fuzz_target;
use psrp_fuzz::{SafeValue, eq_lossy, normalize};
use psrp_rs::clixml::{parse_clixml, to_clixml};

fuzz_target!(|input: SafeValue| {
    let value = input.0;
    let xml = to_clixml(&value);

    let decoded = match parse_clixml(&xml) {
        Ok(v) => v,
        Err(e) => panic!("encoder emitted CLIXML the decoder rejects: {e}\n{xml}"),
    };
    assert_eq!(
        decoded.len(),
        1,
        "one value encoded into {} top-level values\n{xml}",
        decoded.len()
    );

    let expected = normalize(&value);
    assert!(
        eq_lossy(&expected, &decoded[0]),
        "round-trip changed the value\n  xml:      {xml}\n  expected: {expected:?}\n  got:      {:?}",
        decoded[0]
    );
});
