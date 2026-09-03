#![no_main]
//! Layer 3: `Get-Command` metadata and the two pipeline-state parsers.
//!
//! `extract_pipeline_state` decides whether a pipeline is finished, so a
//! parser that panics (or that disagrees with `state_from_xml`) stalls
//! or crashes the receive loop.

use libfuzzer_sys::fuzz_target;
use psrp_rs::clixml::parse_clixml;
use psrp_rs::internal::parse::{
    command_metadata, extract_pipeline_state, parameter_metadata, state_from_xml,
};

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };

    // The two state extractors read the same document through different
    // code paths; whenever the strict one succeeds the lenient one must
    // agree, otherwise the pool and the pipeline see different states.
    let strict = extract_pipeline_state(text).ok();
    let lenient = state_from_xml(text);
    if let (Some(a), Some(b)) = (strict, lenient) {
        assert_eq!(a, b, "pipeline state parsers disagree on:\n{text}");
    }

    if let Ok(values) = parse_clixml(text) {
        for value in &values {
            let _ = command_metadata(value);
            let _ = parameter_metadata(value);
        }
    }
});
