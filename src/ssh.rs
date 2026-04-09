//! SSH transport for MS-PSRP.
//!
//! Gated behind the `ssh` Cargo feature. Connects to a remote host via
//! SSH, opens the `powershell` subsystem, and ferries raw PSRP fragments
//! over stdin/stdout — no WinRM, no SOAP, no base64.
//!
//! # Example
//!
//! ```no_run
//! use psrp_rs::ssh::{SshConfig, SshAuth, SshPsrpTransport};
//! use psrp_rs::RunspacePool;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let transport = SshPsrpTransport::connect(SshConfig {
//!     host: "linux-host".into(),
//!     port: 22,
//!     username: "admin".into(),
//!     auth: SshAuth::Password("s3cret".into()),
//!     ..SshConfig::default()
//! }).await?;
//!
//! let mut pool = RunspacePool::open_with_transport(transport).await?;
//! let out = pool.run_script("Get-Date").await?;
//! let _ = pool.close().await;
//! # Ok(())
//! # }
//! ```

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use russh::ChannelMsg;
use russh::keys::key::PrivateKeyWithHashAlg;
use tokio::sync::Mutex;
use tracing::{debug, warn};

use crate::error::{PsrpError, Result};
use crate::transport::PsrpTransport;

/// SSH connection parameters.
#[derive(Debug, Clone)]
pub struct SshConfig {
    /// Remote hostname or IP.
    pub host: String,
    /// SSH port (default 22).
    pub port: u16,
    /// Username for SSH authentication.
    pub username: String,
    /// Authentication method.
    pub auth: SshAuth,
    /// SSH subsystem name (default `"powershell"`).
    pub subsystem: String,
    /// TCP connect timeout.
    pub connect_timeout: Duration,
}

impl Default for SshConfig {
    fn default() -> Self {
        Self {
            host: String::new(),
            port: 22,
            username: String::new(),
            auth: SshAuth::Agent,
            subsystem: "powershell".into(),
            connect_timeout: Duration::from_secs(30),
        }
    }
}

/// SSH authentication method.
#[derive(Debug, Clone)]
pub enum SshAuth {
    /// Password authentication.
    Password(String),
    /// Private key file with optional passphrase.
    PrivateKey {
        path: PathBuf,
        passphrase: Option<String>,
    },
    /// Use the running SSH agent.
    Agent,
}

/// Client handler for russh — accepts all server host keys.
///
/// Production callers should replace this with proper known-hosts
/// checking via a custom `SshPsrpTransport::connect_with_handler`.
struct ClientHandler;

#[async_trait]
impl russh::client::Handler for ClientHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        _server_public_key: &ssh_key::PublicKey,
    ) -> std::result::Result<bool, Self::Error> {
        // Accept all host keys. Override for production.
        Ok(true)
    }
}

/// PSRP transport over an SSH subsystem channel.
///
/// Fragments are written raw to the channel's stdin and read raw from
/// its stdout. The `Reassembler` in the runspace pool handles
/// arbitrary byte boundaries.
pub struct SshPsrpTransport {
    channel: Arc<Mutex<russh::Channel<russh::client::Msg>>>,
    handle: Arc<Mutex<russh::client::Handle<ClientHandler>>>,
    closed: bool,
}

impl std::fmt::Debug for SshPsrpTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SshPsrpTransport")
            .field("closed", &self.closed)
            .finish()
    }
}

impl SshPsrpTransport {
    /// Connect to the remote host and open the PowerShell subsystem.
    pub async fn connect(config: SshConfig) -> Result<Self> {
        let ssh_config = russh::client::Config::default();
        let addr = format!("{}:{}", config.host, config.port);
        debug!(%addr, "SSH: connecting");

        let mut handle = tokio::time::timeout(
            config.connect_timeout,
            russh::client::connect(Arc::new(ssh_config), &addr, ClientHandler),
        )
        .await
        .map_err(|_| PsrpError::protocol(format!("SSH connect timeout to {addr}")))?
        .map_err(|e| PsrpError::protocol(format!("SSH connect: {e}")))?;

        // Authenticate
        let authenticated = match &config.auth {
            SshAuth::Password(pw) => handle
                .authenticate_password(&config.username, pw)
                .await
                .map_err(|e| PsrpError::protocol(format!("SSH password auth: {e}")))?,
            SshAuth::PrivateKey { path, passphrase } => {
                let private_key = russh_keys::load_secret_key(path, passphrase.as_deref())
                    .map_err(|e| PsrpError::protocol(format!("SSH key load: {e}")))?;
                let key = PrivateKeyWithHashAlg::new(Arc::new(private_key), None)
                    .map_err(|e| PsrpError::protocol(format!("SSH key prep: {e}")))?;
                handle
                    .authenticate_publickey(&config.username, key)
                    .await
                    .map_err(|e| PsrpError::protocol(format!("SSH pubkey auth: {e}")))?
            }
            SshAuth::Agent => {
                return Err(PsrpError::protocol(
                    "SSH agent auth not yet implemented — use Password or PrivateKey",
                ));
            }
        };

        if !authenticated {
            return Err(PsrpError::protocol("SSH authentication failed"));
        }
        debug!("SSH: authenticated");

        // Open channel + request subsystem
        let channel = handle
            .channel_open_session()
            .await
            .map_err(|e| PsrpError::protocol(format!("SSH channel open: {e}")))?;

        channel
            .request_subsystem(true, &config.subsystem)
            .await
            .map_err(|e| PsrpError::protocol(format!("SSH subsystem request: {e}")))?;
        debug!(subsystem = %config.subsystem, "SSH: subsystem opened");

        Ok(Self {
            channel: Arc::new(Mutex::new(channel)),
            handle: Arc::new(Mutex::new(handle)),
            closed: false,
        })
    }
}

#[async_trait]
impl PsrpTransport for SshPsrpTransport {
    async fn send_fragment(&self, bytes: &[u8]) -> Result<()> {
        let channel = self.channel.lock().await;
        channel
            .data(bytes)
            .await
            .map_err(|e| PsrpError::protocol(format!("SSH send: {e}")))?;
        Ok(())
    }

    async fn recv_chunk(&mut self) -> Result<Vec<u8>> {
        let mut channel = self.channel.lock().await;
        loop {
            match channel.wait().await {
                Some(ChannelMsg::Data { data }) => {
                    let bytes = data.to_vec();
                    if bytes.is_empty() {
                        continue;
                    }
                    return Ok(bytes);
                }
                Some(ChannelMsg::ExtendedData { data, ext: 1 }) => {
                    // stderr — log and skip
                    let text = String::from_utf8_lossy(&data);
                    debug!(stderr = %text, "SSH stderr");
                    continue;
                }
                Some(ChannelMsg::Eof) | None => {
                    // Channel closed — return empty to signal EOF
                    return Ok(Vec::new());
                }
                Some(_other) => {
                    continue;
                }
            }
        }
    }

    async fn signal_stop(&self) -> Result<()> {
        // SSH doesn't have a direct Ctrl+C equivalent via the protocol.
        // The best approximation is sending a SIGINT via the "signal"
        // SSH request, but not all servers honor it. Log a warning.
        warn!("signal_stop on SSH transport is a no-op; close the channel to abort");
        Ok(())
    }

    async fn close_shell(&mut self) -> Result<()> {
        if self.closed {
            return Ok(());
        }
        self.closed = true;
        {
            let channel = self.channel.lock().await;
            let _ = channel.eof().await;
            let _ = channel.close().await;
        }
        let handle = self.handle.lock().await;
        handle
            .disconnect(russh::Disconnect::ByApplication, "psrp-rs close", "en")
            .await
            .map_err(|e| PsrpError::protocol(format!("SSH disconnect: {e}")))?;
        debug!("SSH: session closed");
        Ok(())
    }
}

impl Drop for SshPsrpTransport {
    fn drop(&mut self) {
        if !self.closed {
            warn!("SshPsrpTransport dropped without close — SSH session may leak");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ssh_config_defaults() {
        let cfg = SshConfig::default();
        assert_eq!(cfg.port, 22);
        assert_eq!(cfg.subsystem, "powershell");
        assert_eq!(cfg.connect_timeout, Duration::from_secs(30));
    }

    #[test]
    fn ssh_auth_variants() {
        let _pw = SshAuth::Password("secret".into());
        let _key = SshAuth::PrivateKey {
            path: PathBuf::from("/home/user/.ssh/id_rsa"),
            passphrase: None,
        };
        let _agent = SshAuth::Agent;
    }

    #[test]
    fn debug_format() {
        let s = format!(
            "{:?}",
            SshConfig {
                host: "test".into(),
                ..SshConfig::default()
            }
        );
        assert!(s.contains("test"));
    }
}
