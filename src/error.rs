//! Error type for the `psrp-rs` crate.

use thiserror::Error;

/// Errors raised by `psrp-rs` operations.
///
/// Transport-level failures from `winrm-rs` are wrapped via `From<WinrmError>`.
#[derive(Debug, Error)]
pub enum PsrpError {
    /// Transport-level error from `winrm-rs`.
    #[error(transparent)]
    Winrm(#[from] winrm_rs::WinrmError),

    /// PSRP protocol-level error (unexpected message, bad state transition, …).
    #[error("PSRP protocol: {0}")]
    Protocol(String),

    /// CLIXML parse / encode failure.
    #[error("CLIXML: {0}")]
    Clixml(String),

    /// Fragment reassembly failure (truncated header, inconsistent blob length, …).
    #[error("fragment reassembly: {0}")]
    Fragment(String),

    /// The runspace pool was in the wrong state for the requested operation.
    #[error("runspace pool not in state {expected}, got {actual}")]
    BadState {
        /// The state that was expected.
        expected: String,
        /// The state that was actually observed.
        actual: String,
    },

    /// The pipeline was stopped by the caller or by the server.
    #[error("pipeline stopped")]
    Stopped,

    /// The pipeline failed on the server side (a `PipelineState=Failed` message).
    #[error("pipeline failed: {0}")]
    PipelineFailed(String),

    /// An operation was cancelled.
    #[error("operation cancelled")]
    Cancelled,
}

impl PsrpError {
    pub(crate) fn protocol(msg: impl Into<String>) -> Self {
        Self::Protocol(msg.into())
    }

    pub(crate) fn clixml(msg: impl Into<String>) -> Self {
        Self::Clixml(msg.into())
    }

    pub(crate) fn fragment(msg: impl Into<String>) -> Self {
        Self::Fragment(msg.into())
    }
}

/// Convenience alias.
pub type Result<T> = std::result::Result<T, PsrpError>;

/// How much of a message the server wrote an error message quotes, in
/// characters.
pub(crate) const MAX_SERVER_MESSAGE_CHARS: usize = 1024;

/// The first `max_chars` characters of `text`, with the characters that
/// could rewrite a terminal or a log line escaped as by `escape_debug`:
/// controls (C0, DEL, C1: ESC, BEL, a lone CR...), line and paragraph
/// separators, and the invisible format characters among them the bidi
/// embeddings, overrides and isolates. Printable text, quotes and
/// backslashes are kept as they are, so a message stays readable.
pub(crate) fn escape_remote_text(text: &str, max_chars: usize) -> String {
    let mut out = String::new();
    for c in text.chars().take(max_chars) {
        if rewrites_output(c) {
            out.extend(c.escape_debug());
        } else {
            out.push(c);
        }
    }
    if text.chars().nth(max_chars).is_some() {
        out.push('…');
    }
    out
}

/// Whether `c` can move the cursor, ring, reorder or hide text once printed.
pub(crate) fn rewrites_output(c: char) -> bool {
    c.is_control()
        || matches!(
            c,
            '\u{00AD}' // soft hyphen
            | '\u{061C}' // Arabic letter mark (bidi)
            | '\u{180E}' // Mongolian vowel separator
            | '\u{200B}'..='\u{200F}' // zero-width characters, LRM, RLM
            | '\u{2028}'..='\u{202E}' // line and paragraph separators, bidi embeddings, overrides
            | '\u{2060}'..='\u{206F}' // word joiner, invisible operators, bidi isolates
            | '\u{FEFF}' // zero-width no-break space
            | '\u{FFF9}'..='\u{FFFB}' // interlinear annotation
            | '\u{E0000}'..='\u{E007F}' // tags
        )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_variants() {
        assert!(
            PsrpError::protocol("x")
                .to_string()
                .contains("PSRP protocol")
        );
        assert!(PsrpError::clixml("x").to_string().contains("CLIXML"));
        assert!(
            PsrpError::fragment("x")
                .to_string()
                .contains("fragment reassembly")
        );
        assert!(
            PsrpError::BadState {
                expected: "Opened".into(),
                actual: "Opening".into(),
            }
            .to_string()
            .contains("Opened")
        );
        assert_eq!(PsrpError::Stopped.to_string(), "pipeline stopped");
        assert!(
            PsrpError::PipelineFailed("boom".into())
                .to_string()
                .contains("boom")
        );
        assert_eq!(PsrpError::Cancelled.to_string(), "operation cancelled");
    }

    #[test]
    fn from_winrm_error() {
        let we = winrm_rs::WinrmError::Timeout(5);
        let pe: PsrpError = we.into();
        assert!(matches!(pe, PsrpError::Winrm(_)));
    }
}
