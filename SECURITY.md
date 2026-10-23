# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 3.1.x   | Yes       |
| 3.0.x   | Yes       |
| < 3.0   | No        |

2.0.x ignores some `known_hosts` revocations (see the 3.0.0 entry of
`CHANGELOG.md`); upgrade rather than wait for a fix there.

## Reporting a Vulnerability

If you discover a security vulnerability in psrp-rs, please report it responsibly.

**Do NOT open a public GitHub issue for security vulnerabilities.**

Use [GitHub Security Advisories](../../security/advisories/new) to report privately.

### What to Include

- Description of the vulnerability
- Steps to reproduce (or a minimal input that triggers it)
- Potential impact
- Suggested fix (if any)

## Scope

psrp-rs parses data received from a remote PowerShell host (PSRP fragments, messages and CLIXML, the `EncryptedSessionKey` message and the key it wraps, and with the `ssh` feature the PowerShell out-of-process stream received over SSH), handles credentials through `winrm-rs`, and with the `ssh` feature verifies SSH host keys (`known_hosts`, pinned fingerprints) and holds the SSH password or key passphrase. Reports about parser crashes, unbounded resource use on hostile input, credential exposure, host-key verification that accepts a key OpenSSH would refuse, or TLS/authentication weaknesses are in scope.

## Supply Chain

- `unsafe_code` is forbidden in this crate (`unsafe_code = "forbid"`).
- Dependencies are checked in CI with `cargo deny` (advisories, licenses, bans, sources; yanked crates are denied).
- `Cargo.lock` is committed and CI builds with `--locked`.
