# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 2.0.x   | Yes       |
| < 2.0   | No        |

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

psrp-rs parses data received from a remote PowerShell host (PSRP fragments, messages and CLIXML) and handles credentials through `winrm-rs`. Reports about parser crashes, unbounded resource use on hostile input, credential exposure, or TLS/authentication weaknesses are in scope.

## Supply Chain

- `unsafe_code` is forbidden in this crate (`unsafe_code = "forbid"`).
- Dependencies are checked in CI with `cargo deny` (advisories, licenses, bans, sources; yanked crates are denied).
- `Cargo.lock` is committed and CI builds with `--locked`.
