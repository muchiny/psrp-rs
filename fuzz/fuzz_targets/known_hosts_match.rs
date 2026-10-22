#![no_main]
//! Layer 5: the SSH `known_hosts` host matcher.
//!
//! `glob_match` decides whether a host key is trusted. A pattern that
//! makes it blow the stack or run for ever turns host-key verification
//! into a denial of service, and a matcher that accepts a host it should
//! not is a straight MITM hole — so both the termination and the
//! semantics are asserted here, up to the verdict on a whole
//! `known_hosts` file.

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use psrp_rs::internal::ssh::{
    KnownHosts, KnownHostsVerdict, PublicKey, constant_time_eq, glob_match, host_matches_hashed,
    host_matches_patterns, known_hosts_lookup_name, known_hosts_verdict,
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
    known_hosts: String,
}

fuzz_target!(|input: Input| {
    let patterns: Vec<String> = input.patterns.into_iter().take(16).collect();

    // The lookup name ignores case, is already canonical, and on any port
    // but 22 is the port-22 name in brackets.
    let lookup = known_hosts_lookup_name(&input.host, input.port);
    let upper = input.host.to_ascii_uppercase();
    assert_eq!(lookup, known_hosts_lookup_name(&upper, input.port));
    let bare = known_hosts_lookup_name(&input.host, 22);
    assert_eq!(bare, known_hosts_lookup_name(&bare, 22), "not canonical");
    if input.port != 22 {
        assert_eq!(lookup, format!("[{bare}]:{}", input.port));
    }

    let _ = host_matches_patterns(&patterns, &lookup);

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
            assert!(
                glob_match(pattern, pattern),
                "{pattern:?} does not match itself"
            );
        }
    }

    let _ = host_matches_hashed(&input.salt, &input.expected, &input.host);

    // The verdict on a whole file, for the keys the file itself lists,
    // looked up as the server presents them: key data, no comment.
    let listed: Vec<PublicKey> = KnownHosts::new(&input.known_hosts)
        .filter_map(Result::ok)
        .map(|entry| entry.public_key().clone())
        .take(4)
        .collect();
    let tabbed = input.known_hosts.replace(' ', "\t");
    let spaced = input.known_hosts.replace(' ', "  ");
    for listed_key in &listed {
        let key = PublicKey::from(listed_key.key_data().clone());
        let verdict = known_hosts_verdict(&input.known_hosts, &input.host, input.port, &key);
        // Host names are case-insensitive, hashed entries included.
        assert_eq!(
            verdict,
            known_hosts_verdict(&input.known_hosts, &upper, input.port, &key),
            "verdict depends on the case of {:?}",
            input.host
        );
        // ssh(1) splits fields on any run of spaces and tabs.
        for respaced in [&tabbed, &spaced] {
            assert_eq!(
                verdict,
                known_hosts_verdict(respaced, &input.host, input.port, &key),
                "verdict depends on how fields are spaced"
            );
        }
        // `@revoked * KEY comment` revokes the key for every host on every
        // port, whatever the rest of the file says; the line keeps the
        // comment the file gave the key, the server's key has none.
        if let Ok(openssh) = listed_key.to_openssh() {
            let revoked = format!("@revoked * {openssh}\n{}", input.known_hosts);
            assert_eq!(
                known_hosts_verdict(&revoked, &input.host, input.port, &key),
                KnownHostsVerdict::Revoked,
                "wildcard revocation ignored for {:?} port {}",
                input.host,
                input.port
            );
        }
    }

    // Constant-time comparison must still be a correct comparison.
    assert_eq!(
        constant_time_eq(&input.left, &input.right),
        input.left == input.right,
        "constant_time_eq disagrees with =="
    );
});
