#![no_main]
//! Layer 5: the SSH `known_hosts` host matcher.
//!
//! `glob_match` decides whether a host key is trusted. A pattern that
//! makes it blow the stack or run for ever turns host-key verification
//! into a denial of service, and a matcher that accepts a host it should
//! not is a straight MITM hole — so both the termination and the
//! semantics are asserted here.

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use psrp_rs::internal::ssh::{
    constant_time_eq, glob_match, host_matches_hashed, host_matches_patterns,
    parse_pattern_host_port,
};

#[derive(Debug, Arbitrary)]
struct Input {
    patterns: Vec<String>,
    host: String,
    port: u16,
    salt: Vec<u8>,
    expected: [u8; 20],
    left: Vec<u8>,
    right: Vec<u8>,
}

fuzz_target!(|input: Input| {
    let patterns: Vec<String> = input.patterns.into_iter().take(16).collect();

    let _ = host_matches_patterns(&patterns, &input.host, input.port);

    for pattern in &patterns {
        let matched = glob_match(pattern, &input.host);
        // A pattern with no wildcard is a plain case-insensitive compare.
        if !pattern.contains(['*', '?']) {
            assert_eq!(
                matched,
                pattern.eq_ignore_ascii_case(&input.host),
                "literal pattern {pattern:?} mismatched host {:?}",
                input.host
            );
        }
        // `*` matches anything, always.
        assert!(glob_match("*", pattern), "'*' failed to match {pattern:?}");
        // A pattern always matches itself when it has no wildcards.
        if !pattern.contains(['*', '?']) {
            assert!(glob_match(pattern, pattern), "{pattern:?} does not match itself");
        }

        let (host_part, port_part) = parse_pattern_host_port(pattern);
        if port_part.is_none() {
            assert_eq!(host_part, pattern, "port-less pattern was rewritten");
        }
    }

    let _ = host_matches_hashed(&input.salt, &input.expected, &input.host);

    // Constant-time comparison must still be a correct comparison.
    assert_eq!(
        constant_time_eq(&input.left, &input.right),
        input.left == input.right,
        "constant_time_eq disagrees with =="
    );
});
