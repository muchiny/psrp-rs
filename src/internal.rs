//! Internal entry points for the `fuzz/` targets. **Not a public API.**
//!
//! Everything here is gated behind the `__internal` feature. It exists so
//! that `fuzz/fuzz_targets/*` can reach parsers and helpers that are
//! deliberately *not* part of the crate's published surface — the
//! alternative would be to widen the real API just to make it fuzzable,
//! which is worse.
//!
//! The items below are thin `pub` wrappers around `pub(crate)` functions
//! rather than `pub use` re-exports, precisely so that turning the
//! feature off leaves the real API untouched.
//!
//! Do not enable `__internal` from downstream code: any item below may
//! change signature or disappear without a SemVer bump.

use crate::clixml::PsValue;
use crate::error::Result;
use crate::pipeline::PipelineState;

/// Base64 helpers behind the CLIXML `<BA>` codec.
pub mod base64 {
    /// The CLIXML `<BA>` base64 encoder (`clixml::encode::base64_encode`).
    #[must_use]
    pub fn encode(bytes: &[u8]) -> String {
        crate::clixml::encode::base64_encode(bytes)
    }

    /// The CLIXML `<BA>` base64 decoder (`clixml::encode::base64_decode`).
    #[must_use]
    pub fn decode(s: &str) -> Option<Vec<u8>> {
        crate::clixml::encode::base64_decode(s)
    }
}

/// Small parsers that live inside larger async modules and are otherwise
/// unreachable from outside the crate.
pub mod parse {
    use super::{PipelineState, PsValue, Result};

    /// Extract a `<PipelineState>` value out of a `PipelineState` message body.
    pub fn extract_pipeline_state(xml: &str) -> Result<PipelineState> {
        crate::pipeline::extract_pipeline_state(xml)
    }

    /// Render a list of CLIXML error values into a human-readable string.
    #[must_use]
    pub fn describe_errors(errors: &[PsValue]) -> String {
        crate::pipeline::describe_errors(errors)
    }

    /// The `PipelineFailed` message (`pipeline::failure_message`).
    pub fn failure_message(state_data: &str, errors: &[PsValue]) -> String {
        crate::pipeline::failure_message(state_data, errors)
    }

    /// Best-effort `PipelineState` extraction used by the metadata helper.
    #[must_use]
    pub fn state_from_xml(xml: &str) -> Option<PipelineState> {
        crate::metadata::state_from_xml(xml)
    }

    /// Decode a `Get-Command` metadata object.
    #[must_use]
    pub fn command_metadata(value: &PsValue) -> Option<crate::metadata::CommandMetadata> {
        crate::metadata::CommandMetadata::from_ps_object(value)
    }

    /// Decode a single parameter descriptor out of a metadata object.
    #[must_use]
    pub fn parameter_metadata(value: &PsValue) -> Option<crate::metadata::ParameterMetadata> {
        crate::metadata::ParameterMetadata::from_ps_value(value)
    }
}

/// CLIXML builders that embed untrusted values into XML.
pub mod build {
    use super::PsValue;

    /// Build the CLIXML body of a successful host-call response.
    #[must_use]
    pub fn host_response_body(ci: i64, mi: i64, value: &PsValue) -> String {
        crate::runspace::pool::build_host_response_body(ci, mi, value)
    }

    /// Build the CLIXML body of a failed host-call response.
    #[must_use]
    pub fn host_response_error_body(ci: i64, mi: i64, message: &str) -> String {
        crate::runspace::pool::build_host_response_error_body(ci, mi, message)
    }
}

/// The in-memory transport, so a fuzz target can drive the real async
/// runspace pool with attacker-controlled bytes and no network.
pub mod transport {
    pub use crate::transport::mock::MockTransport;
}

/// Direct access to the runspace pool's receive loop.
pub mod pool {
    use crate::error::Result;
    use crate::message::PsrpMessage;
    use crate::runspace::RunspacePool;
    use crate::transport::PsrpTransport;

    /// Pull and decode the next PSRP message, exactly as the pool's own
    /// drivers do.
    pub async fn next_message<T: PsrpTransport>(pool: &mut RunspacePool<T>) -> Result<PsrpMessage> {
        pool.next_message().await
    }
}

/// `known_hosts` host-pattern matching (SSH transport).
#[cfg(feature = "ssh")]
pub mod ssh {
    pub use russh::keys::ssh_key::{PublicKey, known_hosts::KnownHosts};

    /// What a `known_hosts` text says about one host key.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum KnownHostsVerdict {
        /// An unmarked entry for the host lists the key.
        Trusted,
        /// An `@revoked` entry for the host lists the key.
        Revoked,
        /// No entry vouches for the key.
        NotTrusted,
    }

    /// Look a host key up in the text of a `known_hosts` file, as the
    /// `KnownHosts` host-key policy does.
    #[must_use]
    pub fn known_hosts_verdict(
        contents: &str,
        host: &str,
        port: u16,
        key: &PublicKey,
    ) -> KnownHostsVerdict {
        use crate::ssh::KnownHostsVerdict as V;
        match crate::ssh::known_hosts_verdict(contents, host, port, key) {
            V::Trusted => KnownHostsVerdict::Trusted,
            V::Revoked => KnownHostsVerdict::Revoked,
            V::NotTrusted => KnownHostsVerdict::NotTrusted,
        }
    }

    /// The name ssh(1) looks `host:port` up under in `known_hosts`.
    #[must_use]
    pub fn known_hosts_lookup_name(host: &str, port: u16) -> String {
        crate::ssh::known_hosts_lookup_name(host, port)
    }

    /// OpenSSH glob matching (`*` / `?`, case-insensitive).
    #[must_use]
    pub fn glob_match(pattern: &str, target: &str) -> bool {
        crate::ssh::glob_match(pattern, target)
    }

    /// Match a lookup name against a `known_hosts` pattern list.
    #[must_use]
    pub fn host_matches_patterns(patterns: &[String], lookup: &str) -> bool {
        crate::ssh::host_matches_patterns(patterns, lookup)
    }

    /// Match a host against a hashed (`|1|salt|hash`) `known_hosts` entry.
    #[must_use]
    pub fn host_matches_hashed(salt: &[u8], expected: &[u8; 20], host: &str) -> bool {
        crate::ssh::host_matches_hashed(salt, expected, host)
    }

    /// Length-checked constant-time byte comparison.
    #[must_use]
    pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
        crate::ssh::constant_time_eq(a, b)
    }
}

/// The OutOfProc line codec (SSH transport).
#[cfg(feature = "ssh")]
pub mod out_of_proc {
    /// The splitter's line limit.
    pub const MAX_LINE_BYTES: usize = crate::out_of_proc::MAX_LINE_BYTES;

    /// Parses one line as the SSH transport does; on success, the line
    /// PowerShell's writer produces for the same packet, without its `\n`.
    /// `None` for a blank line or an error.
    #[must_use]
    pub fn reencode(line: &str) -> Option<String> {
        let packet = crate::out_of_proc::parse_line(line).ok()??;
        let mut out = packet.to_line();
        out.pop();
        Some(out)
    }

    /// Feeds `chunks` in order to a fresh line splitter; `None` as soon as
    /// it reports an error, whatever lines it completed before that error.
    #[must_use]
    pub fn split(chunks: &[&[u8]]) -> Option<Vec<String>> {
        let mut splitter = crate::out_of_proc::LineSplitter::new();
        let mut lines = Vec::new();
        for chunk in chunks {
            let (done, error) = splitter.push(chunk);
            if error.is_some() {
                return None;
            }
            lines.extend(done);
        }
        Some(lines)
    }
}
