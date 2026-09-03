#![no_main]
//! Layer 3: the typed views over decoded CLIXML.
//!
//! `FromPsObject` implementations walk server-controlled property maps
//! (`Exception.Message`, `CategoryInfo.Category`, `InvocationInfo`, …).
//! They must return `None` on anything unexpected instead of panicking,
//! and must never disagree with themselves across two identical inputs.

use libfuzzer_sys::fuzz_target;
use psrp_rs::clixml::parse_clixml;
use psrp_rs::internal::parse::describe_errors;
use psrp_rs::records::{
    ErrorRecord, FromPsObject, InformationRecord, ProgressRecord, TraceRecord, WarningRecord,
};

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let Ok(values) = parse_clixml(text) else {
        return;
    };

    for value in &values {
        // Every record type sees the same value: a server can send an
        // `ErrorRecord` shape on the warning stream and vice versa.
        let error = ErrorRecord::from_ps_object(value);
        assert_eq!(
            error.is_some(),
            ErrorRecord::from_ps_object(value).is_some(),
            "ErrorRecord decoding is not deterministic"
        );
        let _ = WarningRecord::from_ps_object(value);
        let _ = InformationRecord::from_ps_object(value);
        let _ = ProgressRecord::from_ps_object(value);
        let _ = TraceRecord::from_ps_object(value);
    }

    // `describe_errors` renders untrusted values into the message of a
    // `PsrpError`, so it gets the whole batch too.
    let _ = describe_errors(&values);
});
