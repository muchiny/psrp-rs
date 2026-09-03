#![no_main]
//! Layer 1: the CLIXML parser, the widest attack surface in the crate.
//!
//! Every PSRP message body is CLIXML produced by the remote host. The
//! parser must survive unknown elements, unbalanced tags, bogus
//! `<Ref>` chains, `_xHHHH_` escapes, CDATA, BOMs and deep nesting.

use libfuzzer_sys::fuzz_target;
use psrp_rs::clixml::{parse_clixml, to_clixml};

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let Ok(values) = parse_clixml(text) else {
        return;
    };

    // Whatever we managed to decode must survive a re-encode. This turns
    // the decoder target into an encoder target for free, and catches
    // values that the decoder can produce but the encoder cannot express.
    for value in &values {
        let xml = to_clixml(value);
        let again = parse_clixml(&xml).expect("re-parse of self-encoded value");
        assert_eq!(
            again.len(),
            1,
            "to_clixml produced {} top-level values instead of 1",
            again.len()
        );
    }
});
