//! Async [MS-PSRP] client for Rust, built on top of [`winrm-rs`].
//!
//! `psrp-rs` implements the PowerShell Remoting Protocol on top of
//! WS-Management. It reuses `winrm-rs` for transport, authentication and
//! SOAP envelope handling, and layers the PSRP fragment/CLIXML protocol on
//! top to deliver:
//!
//! - typed PowerShell objects on the `Output` stream;
//! - isolated `Error`, `Warning`, `Verbose`, `Debug`, `Information` and
//!   `Progress` streams;
//! - a persistent [`RunspacePool`] that keeps a `powershell.exe` process
//!   alive across many pipelines;
//! - a builder-style [`Pipeline`] API.
//!
//! [MS-PSRP]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-psrp/
//! [`winrm-rs`]: https://docs.rs/winrm-rs
//!
//! # Example
//!
//! ```no_run
//! use psrp_rs::{
//!     AuthMethod, RunspacePool, WinrmClient, WinrmConfig, WinrmCredentials, WinrmPsrpTransport,
//! };
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // HTTPS on 5986 with the server certificate validated (the default).
//! // A host with only the stock `Enable-PSRemoting` listener needs
//! // `WinrmConfig::http()` (plain HTTP on 5985, trusted networks only).
//! let client = WinrmClient::new(
//!     WinrmConfig {
//!         auth_method: AuthMethod::Ntlm,
//!         ..WinrmConfig::https()
//!     },
//!     WinrmCredentials::new("administrator", "Passw0rd!", ""),
//! )?;
//!
//! let (rpid, creation) = RunspacePool::<WinrmPsrpTransport>::build_creation_fragments(1, 1)?;
//! let transport = WinrmPsrpTransport::open(&client, "win-host.lab", &creation).await?;
//! let mut pool = RunspacePool::open_from_transport(transport, rpid, 1, 1).await?;
//!
//! let objects = pool
//!     .run_script("Get-Process | Select-Object -First 5 Name, Id")
//!     .await?;
//! for obj in objects {
//!     println!("{obj:?}");
//! }
//!
//! pool.close().await?;
//! # Ok(())
//! # }
//! ```
//!
//! # Scope
//!
//! P0 covers: fragment/CLIXML primitives, opening a pool, running a script,
//! collecting every standard stream. P1 extends to per-stream processing
//! via the [`Pipeline`] builder (already available here) and a blocking
//! wrapper in the [`blocking`] module. P2 items — `<Ref>`-based CLIXML
//! round-tripping, pipeline input streaming, reconnect/disconnect — are
//! still on the roadmap.

#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]

pub mod blocking;
pub mod clixml;
pub mod crypto;
pub mod error;
pub mod fragment;
pub mod host;
#[cfg(feature = "__internal")]
pub mod internal;
pub mod message;
pub mod metadata;
#[cfg(feature = "ssh")]
mod out_of_proc;
pub mod pipeline;
pub mod records;
pub mod runspace;
pub mod shared;
#[cfg(feature = "ssh")]
pub mod ssh;
#[cfg(feature = "ssh")]
pub use ssh::{SshAuth, SshConfig, SshPsrpTransport};
pub mod transport;

pub use clixml::{MAX_NESTING_DEPTH, PsObject, PsValue, RefIdAllocator, parse_clixml, to_clixml};
pub use crypto::{ClientSessionKey, SessionKey};
pub use error::{PsrpError, Result};
pub use host::{BufferedHost, HostCallKind, HostMethodId, NoInteractionHost, PsHost};
pub use metadata::{CommandMetadata, CommandType, ParameterMetadata};
pub use pipeline::{Argument, Command, Pipeline, PipelineHandle, PipelineResult, PipelineState};
pub use records::{
    ErrorCategoryInfo, ErrorRecord, ExceptionInfo, FromPsObject, InformationRecord, InvocationInfo,
    ProgressRecord, TraceRecord, WarningRecord,
};
pub use runspace::{
    DisconnectedPool, PROTOCOL_VERSION, RunspacePool, RunspacePoolState, RunspacePoolStateMachine,
};
pub use shared::SharedRunspacePool;
pub use transport::{PsrpTransport, WinrmPsrpTransport};

// Re-export the `winrm-rs` types commonly needed by callers so they
// don't have to depend on `winrm-rs` directly: the client, its
// configuration and credentials, and what the common 2.x settings need
// (the builder for proxies and trusted certificates, `EncryptionMode` for
// Basic over HTTP, `SecretString` for `WinrmConfig::proxy`). The rarer ones
// (`TlsProvider`, `ProxySessionAuth`, the builder's typestate markers) stay
// in `winrm-rs`. They are the `winrm-rs` 2.x types; a caller that also
// imports `winrm_rs` itself must depend on `winrm-rs = "2"`, or it gets a
// second, distinct set of types.
pub use winrm_rs::{
    AuthMethod, EncryptionMode, SecretString, WinrmClient, WinrmClientBuilder, WinrmConfig,
    WinrmCredentials, WinrmError,
};
