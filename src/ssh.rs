//! SSH transport for MS-PSRP.
//!
//! Gated behind the `ssh` Cargo feature. Connects to a remote host via
//! SSH, opens the `powershell` subsystem, and ferries raw PSRP fragments
//! over stdin/stdout — no WinRM, no SOAP, no base64.
//!
//! # Host-key validation
//!
//! By default the transport validates the server's SSH host key against
//! the user's `~/.ssh/known_hosts` file (see [`HostKeyPolicy::default`]).
//! This is fail-closed: if the host is not present in `known_hosts`, the
//! connection is refused. Other policies are available:
//!
//! * [`HostKeyPolicy::Pinned`] — accept only a key whose SHA-256
//!   fingerprint matches the provided 32-byte value.
//! * [`HostKeyPolicy::KnownHosts`] — point at a custom `known_hosts`
//!   file.
//! * [`HostKeyPolicy::AcceptAny`] — accept any key. **Disables
//!   MITM protection**; only use against ephemeral test hosts where you
//!   have already verified the channel by other means.
//!
//! # Example
//!
//! ```no_run
//! use psrp_rs::ssh::{HostKeyPolicy, SshConfig, SshAuth, SshPsrpTransport};
//! use psrp_rs::RunspacePool;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Host-key validation defaults to ~/.ssh/known_hosts. Override with
//! // `.with_host_key_policy(HostKeyPolicy::Pinned(..) | ::AcceptAny)`.
//! let config = SshConfig::new("linux-host", "admin", SshAuth::Password("s3cret".into()));
//! let transport = SshPsrpTransport::connect(config).await?;
//!
//! let mut pool = RunspacePool::open_with_transport(transport).await?;
//! let out = pool.run_script("Get-Date").await?;
//! let _ = pool.close().await;
//! # Ok(())
//! # }
//! ```

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use hmac::{Hmac, KeyInit, Mac};
use russh::ChannelMsg;
use russh::keys::PublicKeyOrCertificate;
use russh::keys::key::PrivateKeyWithHashAlg;
use russh::keys::ssh_key::{
    self, HashAlg,
    known_hosts::{Entry, HostPatterns, KnownHosts, Marker},
};
pub use secrecy::{ExposeSecret, SecretString};
use sha1_hmac::Sha1;
use tokio::sync::Mutex;
use tracing::{debug, warn};

use crate::error::{PsrpError, Result};
use crate::transport::PsrpTransport;

/// Host-key validation policy for [`SshPsrpTransport`].
///
/// The default ([`HostKeyPolicy::default`]) consults
/// `~/.ssh/known_hosts`. To opt out of validation entirely you must
/// explicitly select [`HostKeyPolicy::AcceptAny`] — this is intentional
/// so that misconfiguration cannot silently turn into a MITM hole.
#[derive(Clone, Debug)]
pub enum HostKeyPolicy {
    /// Accept only a key whose SHA-256 fingerprint matches the provided
    /// 32-byte hash. Generate the value with `ssh-keygen -lf <pubkey>`
    /// (the part after `SHA256:` is base64-encoded; decode it to get the
    /// raw bytes).
    Pinned([u8; 32]),
    /// Validate against an OpenSSH `known_hosts`-format file. Both plain
    /// and hashed (`|1|`) entries are supported. Lines marked
    /// `@cert-authority` are ignored (this transport does not currently
    /// implement certificate-authority validation); `@revoked` entries
    /// always cause the connection to be refused. Keys are compared
    /// without their comment, and fields may be separated by any run of
    /// spaces and tabs.
    ///
    /// The host is looked up as ssh(1) does: as `ssh -G` prints it (lower
    /// case, a numeric address in canonical form: `127.1` is `127.0.0.1`)
    /// on port 22, and as `[host]:port` on any other port. So `*` covers
    /// every port, `[host]:*` every port but 22, and `*.example.com` port
    /// 22 only. Unlike ssh(1) in some setups, nothing is retried under the
    /// bare name when no entry matches `[host]:port`: the key is refused.
    KnownHosts(PathBuf),
    /// Accept any host key. **Disables MITM protection.** Only use for
    /// throwaway test environments where you control the network path.
    AcceptAny,
}

impl Default for HostKeyPolicy {
    fn default() -> Self {
        let mut path = std::env::var_os("HOME")
            .map(PathBuf::from)
            .unwrap_or_default();
        path.push(".ssh/known_hosts");
        Self::KnownHosts(path)
    }
}

/// SSH connection parameters.
///
/// Marked `#[non_exhaustive]`, so it cannot be built with a struct
/// expression from another crate — not even with
/// `..Default::default()`. Use [`SshConfig::new`] and the `with_*`
/// methods:
///
/// ```
/// use psrp_rs::ssh::{HostKeyPolicy, SshAuth, SshConfig};
///
/// let config = SshConfig::new("win-host", "admin", SshAuth::Agent)
///     .with_port(2222)
///     .with_host_key_policy(HostKeyPolicy::AcceptAny);
/// ```
///
/// The fields stay public, so an existing value can still be read and
/// mutated directly. The point of the attribute is that adding a field
/// is no longer a breaking change — which is exactly what
/// `host_key_policy` was in 1.1.0.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct SshConfig {
    /// Remote hostname or IP. [`SshPsrpTransport::connect`] refuses a host
    /// that ssh(1) refuses: empty, starting with `-`, or holding
    /// whitespace, a control character or one of ``'`"$\;&<>|(){},``.
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
    /// Host-key validation policy. Defaults to
    /// [`HostKeyPolicy::default`] which checks `~/.ssh/known_hosts`.
    pub host_key_policy: HostKeyPolicy,
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
            host_key_policy: HostKeyPolicy::default(),
        }
    }
}

impl SshConfig {
    /// Start from the defaults, supplying the three values that have no
    /// sensible default.
    ///
    /// Everything else keeps its default: port 22, the `powershell`
    /// subsystem, a 30-second connect timeout, and
    /// [`HostKeyPolicy::default`] (validate against `~/.ssh/known_hosts`,
    /// fail-closed).
    #[must_use]
    pub fn new(host: impl Into<String>, username: impl Into<String>, auth: SshAuth) -> Self {
        Self {
            host: host.into(),
            username: username.into(),
            auth,
            ..Self::default()
        }
    }

    /// Override the TCP port (default 22).
    #[must_use]
    pub fn with_port(mut self, port: u16) -> Self {
        self.port = port;
        self
    }

    /// Override the SSH subsystem to request (default `powershell`).
    #[must_use]
    pub fn with_subsystem(mut self, subsystem: impl Into<String>) -> Self {
        self.subsystem = subsystem.into();
        self
    }

    /// Override the connect timeout (default 30s).
    #[must_use]
    pub fn with_connect_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout = timeout;
        self
    }

    /// Override how the server's host key is validated.
    ///
    /// The default consults `~/.ssh/known_hosts` and refuses an unknown
    /// host. Only [`HostKeyPolicy::AcceptAny`] disables that, and it
    /// disables MITM protection with it.
    #[must_use]
    pub fn with_host_key_policy(mut self, policy: HostKeyPolicy) -> Self {
        self.host_key_policy = policy;
        self
    }
}

/// SSH authentication method.
///
/// The password and the passphrase are [`SecretString`]s: the copy each
/// `SshAuth` (and each clone of it) holds is wiped when it is dropped, and
/// reading one back takes an explicit [`ExposeSecret::expose_secret`].
/// Build them with `.into()` from a `&str` or a `String`. The value you
/// build one from stays yours to wipe; converting a `String` with spare
/// capacity reallocates it and leaves the old buffer as it was. During
/// [`SshPsrpTransport::connect`], russh wipes the copy of the password it
/// sends; the copies its key loader makes are outside this crate's reach.
/// `Debug` never prints them, so a config can be logged safely.
#[derive(Clone)]
pub enum SshAuth {
    /// Password authentication.
    Password(SecretString),
    /// Private key file with optional passphrase.
    PrivateKey {
        /// OpenSSH private key file.
        path: PathBuf,
        /// Passphrase of an encrypted key file; `None` for a plain one.
        passphrase: Option<SecretString>,
    },
    /// Use the running SSH agent.
    Agent,
}

impl std::fmt::Debug for SshAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Password(_) => f.debug_tuple("Password").field(&"<redacted>").finish(),
            Self::PrivateKey { path, passphrase } => f
                .debug_struct("PrivateKey")
                .field("path", path)
                .field("passphrase", &passphrase.as_ref().map(|_| "<redacted>"))
                .finish(),
            Self::Agent => f.write_str("Agent"),
        }
    }
}

/// Client handler for russh that enforces a [`HostKeyPolicy`].
struct ClientHandler {
    host: String,
    port: u16,
    policy: HostKeyPolicy,
}

impl russh::client::Handler for ClientHandler {
    type Error = russh::Error;

    #[allow(
        clippy::unused_async_trait_impl,
        reason = "signature is fixed by russh::client::Handler"
    )]
    async fn check_server_key(
        &mut self,
        server_public_key: &PublicKeyOrCertificate,
    ) -> std::result::Result<bool, Self::Error> {
        // russh >= 0.63 hands us either a bare host key or an OpenSSH
        // host certificate. We have no CA trust store, so a certificate
        // cannot be validated and is refused unless the caller has
        // explicitly opted out of host-key checking altogether.
        let key = match server_public_key {
            PublicKeyOrCertificate::PublicKey { key, .. } => key,
            PublicKeyOrCertificate::Certificate(cert) => {
                if matches!(self.policy, HostKeyPolicy::AcceptAny) {
                    return Ok(true);
                }
                warn!(
                    host = %self.host,
                    port = self.port,
                    issuer = %cert.key_id(),
                    "SSH host certificate rejected: certificate authorities are not supported"
                );
                return Ok(false);
            }
        };
        match verify_host_key(&self.policy, &self.host, self.port, key) {
            Ok(()) => Ok(true),
            Err(reason) => {
                warn!(host = %self.host, port = self.port, %reason, "SSH host-key rejected");
                Ok(false)
            }
        }
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
    ///
    /// The host key presented by the server is validated according to
    /// [`SshConfig::host_key_policy`] before authentication is
    /// attempted. A failed validation aborts the connection with a
    /// protocol error and **no credentials are sent**.
    pub async fn connect(config: SshConfig) -> Result<Self> {
        // Refused before any lookup, so such a name never reaches a
        // resolver, a log line or a `known_hosts` lookup.
        if !valid_ssh_host(&config.host) {
            return Err(PsrpError::protocol(
                "invalid SSH host: empty, starting with '-', or holding whitespace, \
                 a control character or one of '`\"$\\;&<>|(){},",
            ));
        }
        let ssh_config = russh::client::Config::default();
        let addr = format!("{}:{}", config.host, config.port);
        debug!(%addr, "SSH: connecting");

        let handler = ClientHandler {
            host: config.host.clone(),
            port: config.port,
            policy: config.host_key_policy.clone(),
        };
        let mut handle = tokio::time::timeout(
            config.connect_timeout,
            russh::client::connect(Arc::new(ssh_config), &addr, handler),
        )
        .await
        .map_err(|_| PsrpError::protocol(format!("SSH connect timeout to {addr}")))?
        .map_err(|e| PsrpError::protocol(format!("SSH connect: {e}")))?;

        // Authenticate
        let authenticated = match &config.auth {
            SshAuth::Password(pw) => handle
                .authenticate_password(&config.username, pw.expose_secret())
                .await
                .map_err(|e| PsrpError::protocol(format!("SSH password auth: {e}")))?,
            SshAuth::PrivateKey { path, passphrase } => {
                let passphrase = passphrase.as_ref().map(ExposeSecret::expose_secret);
                let private_key = russh::keys::load_secret_key(path, passphrase)
                    .map_err(|e| PsrpError::protocol(format!("SSH key load: {e}")))?;
                let key = PrivateKeyWithHashAlg::new(Arc::new(private_key), None);
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

        if !authenticated.success() {
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

/// Apply the policy. Returns `Ok(())` if the key should be accepted, or
/// an error describing the rejection reason for logging.
fn verify_host_key(
    policy: &HostKeyPolicy,
    host: &str,
    port: u16,
    key: &ssh_key::PublicKey,
) -> std::result::Result<(), String> {
    match policy {
        HostKeyPolicy::AcceptAny => Ok(()),
        HostKeyPolicy::Pinned(expected) => {
            let fp = key.fingerprint(HashAlg::Sha256);
            let actual = fp
                .sha256()
                .ok_or_else(|| "computed fingerprint was not SHA-256".to_string())?;
            if constant_time_eq(&actual, expected) {
                Ok(())
            } else {
                Err("pinned SHA-256 fingerprint does not match".to_string())
            }
        }
        HostKeyPolicy::KnownHosts(path) => verify_against_known_hosts(path, host, port, key),
    }
}

fn verify_against_known_hosts(
    path: &Path,
    host: &str,
    port: u16,
    key: &ssh_key::PublicKey,
) -> std::result::Result<(), String> {
    let contents = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read known_hosts file {}: {e}", path.display()))?;
    match known_hosts_verdict(&contents, host, port, key) {
        KnownHostsVerdict::Trusted => Ok(()),
        KnownHostsVerdict::Revoked => Err(format!(
            "host key for {host}:{port} explicitly revoked in {}",
            path.display()
        )),
        KnownHostsVerdict::NotTrusted => Err(format!(
            "no matching entry for {host}:{port} in {} — host key not trusted",
            path.display()
        )),
    }
}

/// What a `known_hosts` file says about one host key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KnownHostsVerdict {
    /// An unmarked entry for the host lists the key.
    Trusted,
    /// An `@revoked` entry for the host lists the key.
    Revoked,
    /// No entry vouches for the key.
    NotTrusted,
}

/// Look `key` up for `host:port` in the text of a `known_hosts` file the
/// way ssh(1) does: every entry, plain or hashed, is matched against the
/// one name from [`known_hosts_lookup_name`], keys are compared without
/// their comment, and a revocation wins over any entry that trusts the
/// key.
pub(crate) fn known_hosts_verdict(
    contents: &str,
    host: &str,
    port: u16,
    key: &ssh_key::PublicKey,
) -> KnownHostsVerdict {
    let lookup = known_hosts_lookup_name(host, port);
    let contents = normalize_known_hosts(contents);
    let mut trusted = false;
    for entry in KnownHosts::new(&contents) {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue, // malformed line — skip silently like ssh(1)
        };
        if !host_matches_entry(&entry, &lookup) {
            continue;
        }
        // `PublicKey`'s `==` also compares the comment, which a line
        // copied from a `.pub` file carries and the server's key never does.
        let same_key = entry.public_key().key_data() == key.key_data();
        match entry.marker() {
            Some(Marker::Revoked) if same_key => return KnownHostsVerdict::Revoked,
            Some(Marker::Revoked) => continue,
            // Cert-authority entries are not currently honored — see
            // module docs. Treat them as non-matches.
            Some(Marker::CertAuthority) => continue,
            None => trusted |= same_key,
        }
    }
    if trusted {
        KnownHostsVerdict::Trusted
    } else {
        KnownHostsVerdict::NotTrusted
    }
}

/// ssh(1) splits a `known_hosts` line on any run of spaces and tabs; the
/// `ssh-key` parser wants exactly one space between fields and skips any
/// other line as malformed, an `@revoked` one included. Rewrite every
/// line with single spaces first.
fn normalize_known_hosts(contents: &str) -> String {
    contents
        .lines()
        .map(|line| line.split_ascii_whitespace().collect::<Vec<_>>().join(" "))
        .collect::<Vec<_>>()
        .join("\n")
}

/// The name ssh(1) looks a host up under in `known_hosts`: the host for
/// port 22, `[host]:port` for any other port, with the host as `ssh -G`
/// prints it (see [`canonical_host`]). It is also the name `ssh-keygen -H`
/// hashes.
pub(crate) fn known_hosts_lookup_name(host: &str, port: u16) -> String {
    let host = canonical_host(host);
    if port == 22 {
        host
    } else {
        format!("[{host}]:{port}")
    }
}

/// A numeric address in its canonical form (`127.1` is `127.0.0.1`,
/// `[2001:DB8:0::1]` is `2001:db8::1`), as the resolver reads it and
/// ssh(1) rewrites it; any other host in lower case.
fn canonical_host(host: &str) -> String {
    let unbracketed = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    if let Ok(ip) = unbracketed.parse::<std::net::IpAddr>() {
        return ip.to_string();
    }
    if let Some(ip) = parse_inet_aton(host) {
        return ip.to_string();
    }
    host.to_ascii_lowercase()
}

/// The IPv4 forms `inet_aton(3)` accepts, which the system resolver and
/// so ssh(1) take as addresses: one to four dot-separated numbers, each
/// decimal, octal (leading `0`) or hexadecimal (`0x`), the last one
/// filling every byte the others leave.
fn parse_inet_aton(s: &str) -> Option<std::net::Ipv4Addr> {
    let mut parts = Vec::with_capacity(4);
    for part in s.split('.') {
        let (digits, radix) =
            if let Some(hex) = part.strip_prefix("0x").or_else(|| part.strip_prefix("0X")) {
                (hex, 16)
            } else if part.len() > 1
                && let Some(octal) = part.strip_prefix('0')
            {
                (octal, 8)
            } else {
                (part, 10)
            };
        // `from_str_radix` would also take a sign.
        if digits.is_empty() || !digits.chars().all(|c| c.is_digit(radix)) {
            return None;
        }
        parts.push(u32::from_str_radix(digits, radix).ok()?);
        if parts.len() > 4 {
            return None;
        }
    }
    let (last, leading) = parts.split_last()?;
    if leading.iter().any(|&p| p > 0xff) {
        return None;
    }
    // Bits left for the last number: 32, 24, 16 or 8.
    let free_bits = 32 - 8 * u32::try_from(leading.len()).ok()?;
    if free_bits < 32 && *last >> free_bits != 0 {
        return None;
    }
    let high = leading
        .iter()
        .zip([24u32, 16, 8])
        .fold(0u32, |acc, (&p, shift)| acc | (p << shift));
    Some(std::net::Ipv4Addr::from(high | last))
}

/// ssh(1)'s own check on a host name (`ssh -G` refuses these with
/// "hostname contains invalid characters"): not empty, no leading `-`,
/// no whitespace or control character, none of ``'`"$\;&<>|(){}`` nor
/// the `known_hosts` list separator `,`.
fn valid_ssh_host(host: &str) -> bool {
    !host.is_empty()
        && !host.starts_with('-')
        && !host
            .chars()
            .any(|c| c.is_whitespace() || c.is_control() || "'`\"$\\;&<>|(){},".contains(c))
}

fn host_matches_entry(entry: &Entry, lookup: &str) -> bool {
    match entry.host_patterns() {
        HostPatterns::Patterns(patterns) => host_matches_patterns(patterns, lookup),
        HostPatterns::HashedName { salt, hash } => host_matches_hashed(salt, hash, lookup),
    }
}

/// OpenSSH-style host pattern matching against a name from
/// [`known_hosts_lookup_name`].
///
/// Supports:
/// * literal names (`example.com`, `[example.com]:2222`)
/// * glob wildcards `*` and `?`, which also cover the port
///   (`*` matches every host on every port, `[example.com]:*` every
///   non-default port of one host)
/// * `!pattern` negation — a single negation wins over any positive
///   match on the same line, mirroring ssh(1) behaviour
pub(crate) fn host_matches_patterns(patterns: &[String], lookup: &str) -> bool {
    let mut positive = false;
    for raw in patterns {
        let (negate, pattern) = match raw.strip_prefix('!') {
            Some(rest) => (true, rest),
            None => (false, raw.as_str()),
        };
        if !glob_match(pattern, lookup) {
            continue;
        }
        if negate {
            return false;
        }
        positive = true;
    }
    positive
}

pub(crate) fn glob_match(pattern: &str, target: &str) -> bool {
    glob_match_bytes(pattern.as_bytes(), target.as_bytes())
}

/// Iterative wildcard match with a single backtrack point.
///
/// The obvious recursive formulation ("on `*`, try every split") is
/// exponential: `*a*a*a*a*b` against a long run of `a`s explores every
/// way of distributing the target across the stars, and it recurses once
/// per target byte on top of that. Since patterns come from a
/// `known_hosts` file and the host name comes from the connection being
/// validated, that turns host-key verification into a denial of service
/// — the connection hangs instead of being accepted or refused.
///
/// This version keeps one backtrack position (the most recent `*` and
/// how much of the target it had consumed), which is enough for a
/// pattern language with only `*` and `?`. Worst case is `O(n * m)`
/// with no recursion at all.
fn glob_match_bytes(pattern: &[u8], target: &[u8]) -> bool {
    let mut p = 0usize;
    let mut t = 0usize;
    // Position just past the last `*` seen, and how far the target had
    // advanced when we saw it.
    let mut star: Option<usize> = None;
    let mut star_target = 0usize;

    while t < target.len() {
        match pattern.get(p) {
            Some(b'*') => {
                p += 1;
                star = Some(p);
                star_target = t;
            }
            Some(b'?') => {
                p += 1;
                t += 1;
            }
            Some(c) if c.eq_ignore_ascii_case(&target[t]) => {
                p += 1;
                t += 1;
            }
            // Mismatch: let the last `*` swallow one more target byte.
            _ => match star {
                Some(resume) => {
                    p = resume;
                    star_target += 1;
                    t = star_target;
                }
                None => return false,
            },
        }
    }

    // The target is exhausted; only trailing `*`s may remain.
    while pattern.get(p) == Some(&b'*') {
        p += 1;
    }
    p == pattern.len()
}

pub(crate) fn host_matches_hashed(salt: &[u8], expected: &[u8; 20], host: &str) -> bool {
    // OpenSSH refuses a line whose salt is not exactly one SHA-1 digest
    // long, so it never trusts what that line names.
    if salt.len() != expected.len() {
        return false;
    }
    let mut mac = match Hmac::<Sha1>::new_from_slice(salt) {
        Ok(m) => m,
        Err(_) => return false,
    };
    mac.update(host.as_bytes());
    let computed = mac.finalize().into_bytes();
    constant_time_eq(computed.as_slice(), expected)
}

pub(crate) fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ssh_config_builder_sets_every_field() {
        let cfg = SshConfig::new("host.example", "admin", SshAuth::Agent)
            .with_port(2222)
            .with_subsystem("pwsh")
            .with_connect_timeout(Duration::from_secs(5))
            .with_host_key_policy(HostKeyPolicy::AcceptAny);

        assert_eq!(cfg.host, "host.example");
        assert_eq!(cfg.username, "admin");
        assert!(matches!(cfg.auth, SshAuth::Agent));
        assert_eq!(cfg.port, 2222);
        assert_eq!(cfg.subsystem, "pwsh");
        assert_eq!(cfg.connect_timeout, Duration::from_secs(5));
        assert!(matches!(cfg.host_key_policy, HostKeyPolicy::AcceptAny));
    }

    #[test]
    fn ssh_config_new_keeps_the_safe_defaults() {
        let cfg = SshConfig::new("h", "u", SshAuth::Agent);
        let defaults = SshConfig::default();
        assert_eq!(cfg.port, defaults.port);
        assert_eq!(cfg.subsystem, defaults.subsystem);
        assert_eq!(cfg.connect_timeout, defaults.connect_timeout);
        // Host-key checking must not be weakened by using the builder.
        assert!(matches!(cfg.host_key_policy, HostKeyPolicy::KnownHosts(_)));
    }

    #[test]
    fn ssh_config_defaults() {
        let cfg = SshConfig::default();
        assert_eq!(cfg.port, 22);
        assert_eq!(cfg.subsystem, "powershell");
        assert_eq!(cfg.connect_timeout, Duration::from_secs(30));
        assert!(matches!(cfg.host_key_policy, HostKeyPolicy::KnownHosts(_)));
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

    #[test]
    fn glob_matches_literal_and_wildcards() {
        assert!(glob_match("example.com", "example.com"));
        assert!(glob_match("EXAMPLE.com", "example.com")); // case-insensitive
        assert!(!glob_match("example.com", "other.com"));
        assert!(glob_match("*.example.com", "host.example.com"));
        assert!(!glob_match("*.example.com", "example.com"));
        assert!(glob_match("h?st", "host"));
        assert!(!glob_match("h?st", "hoost"));
    }

    #[test]
    fn glob_matches_star_edge_cases() {
        assert!(glob_match("*", ""));
        assert!(glob_match("*", "anything"));
        assert!(glob_match("**", "anything"));
        assert!(glob_match("a*", "a"));
        assert!(glob_match("*a", "a"));
        assert!(glob_match("a*b*c", "abc"));
        assert!(glob_match("a*b*c", "axxbyyc"));
        assert!(!glob_match("a*b*c", "axxbyy"));
        assert!(!glob_match("*?", ""));
        assert!(glob_match("", ""));
        assert!(!glob_match("", "x"));
        // A `*` must still be able to consume nothing at the very end.
        assert!(glob_match("host*", "host"));
    }

    /// Regression: the previous recursive matcher explored every way of
    /// splitting the target across the stars, so this pattern took
    /// exponential time and hung host-key verification. Found by the
    /// `known_hosts_match` fuzz target.
    #[test]
    fn glob_match_is_not_exponential() {
        let pattern = "*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*b";
        let target = "a".repeat(256);
        let start = std::time::Instant::now();
        assert!(!glob_match(pattern, &target));
        assert!(
            start.elapsed() < std::time::Duration::from_secs(1),
            "glob_match took {:?} — backtracking blew up again",
            start.elapsed()
        );
    }

    fn patterns_match(patterns: &[&str], host: &str, port: u16) -> bool {
        let patterns: Vec<String> = patterns.iter().map(|p| (*p).to_string()).collect();
        host_matches_patterns(&patterns, &known_hosts_lookup_name(host, port))
    }

    fn entry_matches(entry: &Entry, host: &str, port: u16) -> bool {
        host_matches_entry(entry, &known_hosts_lookup_name(host, port))
    }

    #[test]
    fn pattern_match_respects_port_brackets() {
        assert!(patterns_match(&["[example.com]:2222"], "example.com", 2222));
        assert!(!patterns_match(&["[example.com]:2222"], "example.com", 22));
        // bare pattern matches default port only
        assert!(patterns_match(&["example.com"], "example.com", 22));
        assert!(!patterns_match(&["example.com"], "example.com", 2222));
    }

    #[test]
    fn pattern_negation_overrides_positive_match() {
        let patterns = ["*.example.com", "!evil.example.com"];
        assert!(patterns_match(&patterns, "good.example.com", 22));
        assert!(!patterns_match(&patterns, "evil.example.com", 22));
    }

    #[test]
    fn hashed_host_match_via_hmac_sha1() {
        // Reproduce ssh-keygen's hashed-host derivation for `host.example.com`.
        let host = "host.example.com";
        let salt =
            b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14";
        let mut mac = Hmac::<Sha1>::new_from_slice(salt).unwrap();
        mac.update(host.as_bytes());
        let expected: [u8; 20] = mac.finalize().into_bytes().into();
        assert!(host_matches_hashed(salt, &expected, host));
        // A different host must not match.
        assert!(!host_matches_hashed(salt, &expected, "other.example.com"));
    }

    /// The `|1|salt|hash` form `ssh-keygen -H` writes for `name`.
    fn hashed_name(name: &str) -> String {
        let salt: Vec<u8> = (1u8..=20).collect();
        hashed_name_with_salt(name, &salt)
    }

    fn hashed_name_with_salt(name: &str, salt: &[u8]) -> String {
        let mut mac = Hmac::<Sha1>::new_from_slice(salt).unwrap();
        mac.update(name.as_bytes());
        let hash: [u8; 20] = mac.finalize().into_bytes().into();
        HostPatterns::HashedName {
            salt: salt.to_vec(),
            hash,
        }
        .to_string()
    }

    fn hashed_entry(name: &str) -> Entry {
        format!("{} {KEY}", hashed_name(name)).parse().unwrap()
    }

    #[test]
    fn hashed_entry_for_default_port_does_not_match_other_port() {
        let entry = hashed_entry("host.example.com");
        assert!(entry_matches(&entry, "host.example.com", 22));
        assert!(!entry_matches(&entry, "host.example.com", 2222));
    }

    #[test]
    fn hashed_entry_for_non_default_port_uses_bracketed_form() {
        // OpenSSH hashes `[host]:port` when the port is not 22.
        let entry = hashed_entry("[host.example.com]:2222");
        assert!(entry_matches(&entry, "host.example.com", 2222));
        assert!(!entry_matches(&entry, "host.example.com", 22));
        assert!(!entry_matches(&entry, "host.example.com", 2223));
    }

    #[test]
    fn ssh_auth_debug_redacts_secrets() {
        let pw = format!("{:?}", SshAuth::Password("hunter2".into()));
        assert!(!pw.contains("hunter2"), "{pw}");
        let key = format!(
            "{:?}",
            SshAuth::PrivateKey {
                path: PathBuf::from("/k"),
                passphrase: Some("hunter2".into()),
            }
        );
        assert!(!key.contains("hunter2"), "{key}");
        assert!(key.contains("/k"), "{key}");
        let cfg = SshConfig::new("h", "u", SshAuth::Password("hunter2".into()));
        assert!(!format!("{cfg:?}").contains("hunter2"));
    }

    #[test]
    fn ssh_auth_keeps_secrets_in_secret_strings() {
        // Compiles only while the fields are `SecretString`s (a `String`
        // has no `expose_secret`), the type that wipes them on drop.
        let SshAuth::Password(pw) = SshAuth::Password("hunter2".into()) else {
            unreachable!()
        };
        assert_eq!(pw.expose_secret(), "hunter2");
        let key = SshAuth::PrivateKey {
            path: PathBuf::from("/k"),
            passphrase: Some("hunter2".into()),
        };
        let SshAuth::PrivateKey { passphrase, .. } = key else {
            unreachable!()
        };
        assert_eq!(
            passphrase.as_ref().map(ExposeSecret::expose_secret),
            Some("hunter2")
        );
    }

    // Lines produced by `ssh-keygen -H` (OpenSSH) from a plain known_hosts
    // file; unlike the tests above they do not reuse our own HMAC, so a
    // regression in the derivation cannot cancel itself out.
    const KEY: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB9dG4kjRhQTtWTVzd2t27+t0DEHBPW7iOD23TUiYLio";
    // `ssh-keygen -F host.example.com` finds this line.
    const OPENSSH_HASHED_PORT_22: &str =
        "|1|lYwLrkkXUy8VYdhIoABoFOAIbjw=|mkD0YR/iu/f+3KCw7RERu6gNQ2Y=";
    // `ssh-keygen -F '[host.example.com]:2222'` finds this line.
    const OPENSSH_HASHED_PORT_2222: &str =
        "|1|cozVwoXi94RwYGBCGJ9g1AW6EFc=|Vv+J4nPh4vRAM5fgFqPFI0TlKS8=";

    #[test]
    fn openssh_generated_hashed_entries_match() {
        let e22: Entry = format!("{OPENSSH_HASHED_PORT_22} {KEY}").parse().unwrap();
        assert!(entry_matches(&e22, "host.example.com", 22));
        assert!(!entry_matches(&e22, "host.example.com", 2222));
        assert!(!entry_matches(&e22, "other.example.com", 22));
        let e2222: Entry = format!("{OPENSSH_HASHED_PORT_2222} {KEY}").parse().unwrap();
        assert!(entry_matches(&e2222, "host.example.com", 2222));
        assert!(!entry_matches(&e2222, "host.example.com", 22));
        assert!(!entry_matches(&e2222, "other.example.com", 2222));
    }

    #[test]
    fn constant_time_eq_basic() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"abcd"));
    }

    #[test]
    fn known_hosts_rejects_when_file_missing() {
        let dummy_key: ssh_key::PublicKey =
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB9dG4kjRhQTtWTVzd2t27+t0DEHBPW7iOD23TUiYLio"
                .parse()
                .unwrap();
        let policy = HostKeyPolicy::KnownHosts("/this/path/does/not/exist".into());
        let err = verify_host_key(&policy, "example.com", 22, &dummy_key).unwrap_err();
        assert!(err.contains("known_hosts"));
    }

    #[test]
    fn known_hosts_accepts_matching_plain_entry() {
        let key_str =
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB9dG4kjRhQTtWTVzd2t27+t0DEHBPW7iOD23TUiYLio";
        let key: ssh_key::PublicKey = key_str.parse().unwrap();
        let tmp = std::env::temp_dir().join(format!("psrp_known_hosts_{}", std::process::id()));
        std::fs::write(&tmp, format!("example.com {key_str}\n")).unwrap();
        let policy = HostKeyPolicy::KnownHosts(tmp.clone());
        verify_host_key(&policy, "example.com", 22, &key).unwrap();
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn known_hosts_rejects_non_matching_host() {
        let key_str =
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB9dG4kjRhQTtWTVzd2t27+t0DEHBPW7iOD23TUiYLio";
        let key: ssh_key::PublicKey = key_str.parse().unwrap();
        let tmp = std::env::temp_dir().join(format!("psrp_known_hosts_no_{}", std::process::id()));
        std::fs::write(&tmp, format!("example.com {key_str}\n")).unwrap();
        let policy = HostKeyPolicy::KnownHosts(tmp.clone());
        let err = verify_host_key(&policy, "different.com", 22, &key).unwrap_err();
        assert!(err.contains("no matching entry"));
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn pinned_fingerprint_matches() {
        let key_str =
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB9dG4kjRhQTtWTVzd2t27+t0DEHBPW7iOD23TUiYLio";
        let key: ssh_key::PublicKey = key_str.parse().unwrap();
        let fp = key.fingerprint(HashAlg::Sha256);
        let raw = fp.sha256().unwrap();
        let policy = HostKeyPolicy::Pinned(raw);
        verify_host_key(&policy, "irrelevant", 22, &key).unwrap();
        // Mutate a byte to force a mismatch.
        let mut bad = raw;
        bad[0] ^= 0xff;
        let policy_bad = HostKeyPolicy::Pinned(bad);
        assert!(verify_host_key(&policy_bad, "irrelevant", 22, &key).is_err());
    }

    #[test]
    fn accept_any_returns_ok() {
        let key: ssh_key::PublicKey =
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB9dG4kjRhQTtWTVzd2t27+t0DEHBPW7iOD23TUiYLio"
                .parse()
                .unwrap();
        verify_host_key(&HostKeyPolicy::AcceptAny, "x", 22, &key).unwrap();
    }

    /// Build a uniquely-named temp file path keyed on the test name and
    /// pid. Avoids collisions when tests run in parallel.
    fn tmp_path(tag: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "psrp_known_hosts_{}_{}_{}",
            tag,
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    #[test]
    fn known_hosts_revoked_entry_blocks_matching_key() {
        let key_str =
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB9dG4kjRhQTtWTVzd2t27+t0DEHBPW7iOD23TUiYLio";
        let key: ssh_key::PublicKey = key_str.parse().unwrap();
        let tmp = tmp_path("revoked");
        std::fs::write(&tmp, format!("@revoked example.com {key_str}\n")).unwrap();
        let policy = HostKeyPolicy::KnownHosts(tmp.clone());
        let err = verify_host_key(&policy, "example.com", 22, &key).unwrap_err();
        assert!(
            err.contains("revoked"),
            "expected revoked rejection, got: {err}"
        );
        // Both rejections name the host and the port.
        assert!(err.contains("example.com:22"), "{err}");
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn known_hosts_revoked_entry_with_different_key_does_not_falsely_block() {
        // @revoked applies only to the listed key. A different key for
        // the same host must still be evaluated against the rest of the
        // file rather than blanket-rejected.
        let revoked_key =
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB9dG4kjRhQTtWTVzd2t27+t0DEHBPW7iOD23TUiYLio";
        let trusted_key_str =
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILRzpKj+f5Lzt8O6XsBRSJZNwZpRm9rA0kRNH4yp1ZxN";
        let trusted: ssh_key::PublicKey = trusted_key_str.parse().unwrap();
        let tmp = tmp_path("revoked_other_key");
        std::fs::write(
            &tmp,
            format!("@revoked example.com {revoked_key}\nexample.com {trusted_key_str}\n"),
        )
        .unwrap();
        let policy = HostKeyPolicy::KnownHosts(tmp.clone());
        verify_host_key(&policy, "example.com", 22, &trusted).unwrap();
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn known_hosts_cert_authority_entry_does_not_grant_trust() {
        // @cert-authority is currently unsupported — the key it lists
        // must not be treated as a directly-trusted host key.
        let key_str =
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB9dG4kjRhQTtWTVzd2t27+t0DEHBPW7iOD23TUiYLio";
        let key: ssh_key::PublicKey = key_str.parse().unwrap();
        let tmp = tmp_path("cert_authority");
        std::fs::write(&tmp, format!("@cert-authority *.example.com {key_str}\n")).unwrap();
        let policy = HostKeyPolicy::KnownHosts(tmp.clone());
        let err = verify_host_key(&policy, "host.example.com", 22, &key).unwrap_err();
        assert!(
            err.contains("no matching entry"),
            "@cert-authority must not grant direct trust, got: {err}"
        );
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn known_hosts_hashed_entry_full_file_roundtrip() {
        use ssh_key::known_hosts::{Entry, HostPatterns};
        // Build a real hashed entry using HMAC-SHA1, render it via the
        // ssh-key HostPatterns serializer (which handles the base64
        // encoding), write it to a file, then verify end-to-end through
        // verify_host_key.
        let host = "secret.example.com";
        let salt: Vec<u8> =
            b"\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34"
                .to_vec();
        let mut mac = Hmac::<Sha1>::new_from_slice(&salt).unwrap();
        mac.update(host.as_bytes());
        let hash: [u8; 20] = mac.finalize().into_bytes().into();
        let patterns = HostPatterns::HashedName {
            salt: salt.clone(),
            hash,
        };
        let key_str =
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB9dG4kjRhQTtWTVzd2t27+t0DEHBPW7iOD23TUiYLio";
        let key: ssh_key::PublicKey = key_str.parse().unwrap();
        let line = format!("{} {key_str}", patterns.to_string());
        // Sanity: the line we just built is a parseable Entry.
        line.parse::<Entry>().unwrap();
        let tmp = tmp_path("hashed");
        std::fs::write(&tmp, format!("{line}\n")).unwrap();
        let policy = HostKeyPolicy::KnownHosts(tmp.clone());
        verify_host_key(&policy, host, 22, &key).unwrap();
        // Different hostname does not match the same hashed entry.
        let err = verify_host_key(&policy, "other.example.com", 22, &key).unwrap_err();
        assert!(err.contains("no matching entry"));
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn known_hosts_iterates_through_multiple_entries() {
        let trusted_key_str =
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB9dG4kjRhQTtWTVzd2t27+t0DEHBPW7iOD23TUiYLio";
        let other_key_str =
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILRzpKj+f5Lzt8O6XsBRSJZNwZpRm9rA0kRNH4yp1ZxN";
        let trusted: ssh_key::PublicKey = trusted_key_str.parse().unwrap();
        let tmp = tmp_path("multi");
        // Match buried at line 4 of 5.
        std::fs::write(
            &tmp,
            format!(
                "github.com {other_key_str}\n\
                 gitlab.example {other_key_str}\n\
                 # comment line followed by blank\n\
                 \n\
                 example.com {trusted_key_str}\n\
                 backup.example.com {other_key_str}\n",
            ),
        )
        .unwrap();
        let policy = HostKeyPolicy::KnownHosts(tmp.clone());
        verify_host_key(&policy, "example.com", 22, &trusted).unwrap();
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn known_hosts_skips_malformed_lines_and_still_accepts_valid_entry() {
        let key_str =
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB9dG4kjRhQTtWTVzd2t27+t0DEHBPW7iOD23TUiYLio";
        let key: ssh_key::PublicKey = key_str.parse().unwrap();
        let tmp = tmp_path("malformed");
        std::fs::write(
            &tmp,
            format!(
                "this is not a valid known_hosts entry at all\n\
                 |1|incomplete-hashed-host-line\n\
                 example.com {key_str}\n\
                 @nonsense-marker example.com {key_str}\n",
            ),
        )
        .unwrap();
        let policy = HostKeyPolicy::KnownHosts(tmp.clone());
        verify_host_key(&policy, "example.com", 22, &key).unwrap();
        let _ = std::fs::remove_file(&tmp);
    }

    /// The verdict of `contents` on `KEY` as russh hands it over: key data
    /// only, no comment.
    fn verdict(contents: &str, host: &str, port: u16) -> KnownHostsVerdict {
        let key: ssh_key::PublicKey = KEY.parse().unwrap();
        let key = ssh_key::PublicKey::from(key.key_data().clone());
        known_hosts_verdict(contents, host, port, &key)
    }

    #[test]
    fn revoked_wildcard_applies_on_every_port() {
        // The sshd(8) manual's own example. OpenSSH looks `[host]:2222`
        // up for port 2222, and `*` matches that too.
        let file = format!("@revoked * {KEY}\n[host.example.com]:2222 {KEY}\n");
        assert_eq!(
            verdict(&file, "host.example.com", 2222),
            KnownHostsVerdict::Revoked
        );
    }

    #[test]
    fn port_wildcard_pattern_matches_any_non_default_port() {
        let file = format!("[host.example.com]:* {KEY}\n");
        assert_eq!(
            verdict(&file, "host.example.com", 2222),
            KnownHostsVerdict::Trusted
        );
        // Port 22 is looked up as the bare name, which has no brackets.
        assert_eq!(
            verdict(&file, "host.example.com", 22),
            KnownHostsVerdict::NotTrusted
        );
    }

    #[test]
    fn bracketed_default_port_is_not_the_openssh_lookup_name() {
        // ssh(1) never writes `[host]:22` and never looks it up.
        let file = format!("[host.example.com]:22 {KEY}\n");
        assert_eq!(
            verdict(&file, "host.example.com", 22),
            KnownHostsVerdict::NotTrusted
        );
    }

    #[test]
    fn hashed_entry_matches_whatever_the_host_name_case() {
        let file = format!("{} {KEY}\n", hashed_name("host.example.com"));
        assert_eq!(
            verdict(&file, "Host.Example.COM", 22),
            KnownHostsVerdict::Trusted
        );
    }

    #[test]
    fn hashed_revocation_applies_whatever_the_host_name_case() {
        let file = format!(
            "@revoked {} {KEY}\n[*.example.com]:2222 {KEY}\n",
            hashed_name("[host.example.com]:2222")
        );
        assert_eq!(
            verdict(&file, "Host.Example.COM", 2222),
            KnownHostsVerdict::Revoked
        );
    }

    #[test]
    fn trust_line_with_a_key_comment_still_trusts() {
        let file = format!("host.example.com {KEY} admin@laptop\n");
        assert_eq!(
            verdict(&file, "host.example.com", 22),
            KnownHostsVerdict::Trusted
        );
    }

    #[test]
    fn revocation_with_a_key_comment_still_revokes() {
        // A line copied from a `.pub` file carries the key's comment; the
        // server's key never does.
        let file = format!("@revoked * {KEY} compromised\nhost.example.com {KEY}\n");
        assert_eq!(
            verdict(&file, "host.example.com", 22),
            KnownHostsVerdict::Revoked
        );
    }

    #[test]
    fn revocation_written_with_tabs_or_extra_spaces_still_revokes() {
        // ssh(1) splits fields on any run of spaces and tabs.
        let tabbed = KEY.replace(' ', "\t");
        for revoked in [
            format!("@revoked\t*\t{tabbed}"),
            format!("@revoked  * {KEY}"),
            format!("  @revoked * {KEY}"),
            format!("@revoked * {KEY}  \r"),
        ] {
            let file = format!("{revoked}\nhost.example.com {KEY}\n");
            assert_eq!(
                verdict(&file, "host.example.com", 22),
                KnownHostsVerdict::Revoked,
                "{revoked:?}"
            );
        }
    }

    #[test]
    fn trust_line_written_with_tabs_trusts() {
        let file = format!("host.example.com\t{}\n", KEY.replace(' ', "\t"));
        assert_eq!(
            verdict(&file, "host.example.com", 22),
            KnownHostsVerdict::Trusted
        );
    }

    #[test]
    fn numeric_hosts_are_looked_up_in_canonical_form() {
        // What `ssh -G <host>` prints as `hostname` (OpenSSH 10.0), except
        // the bracketed row: ssh(1) takes the port apart and the address
        // bare, whereas `SshConfig::host` may carry the brackets the
        // `host:port` connect string needs, so `[addr]` is read as `addr`.
        for (host, port, lookup) in [
            ("127.1", 22, "127.0.0.1"),
            ("0x7f.1", 22, "127.0.0.1"),
            ("017.0.0.1", 22, "15.0.0.1"),
            ("2001:DB8:0:0::1", 22, "2001:db8::1"),
            ("[2001:db8:0::1]", 2222, "[2001:db8::1]:2222"),
            ("Host.Example.COM", 2222, "[host.example.com]:2222"),
            // Not addresses: kept as written, in lower case.
            ("1.2.3.256", 22, "1.2.3.256"),
            ("256.1", 22, "256.1"),
            ("1.16777216", 22, "1.16777216"),
            ("+1", 22, "+1"),
            ("1.2.3.4.", 22, "1.2.3.4."),
        ] {
            assert_eq!(known_hosts_lookup_name(host, port), lookup, "{host}");
        }
    }

    #[test]
    fn revocation_of_an_address_applies_to_its_short_form() {
        let file = format!("@revoked 127.0.0.1 {KEY}\n127.* {KEY}\n");
        assert_eq!(verdict(&file, "127.1", 22), KnownHostsVerdict::Revoked);
    }

    #[test]
    fn hashed_entry_with_a_salt_that_is_not_20_bytes_is_ignored() {
        // OpenSSH refuses such a line: the salt is an HMAC-SHA1 key of
        // exactly the digest's length.
        let name = hashed_name_with_salt("host.example.com", &[7u8; 16]);
        let file = format!("{name} {KEY}\n");
        assert_eq!(
            verdict(&file, "host.example.com", 22),
            KnownHostsVerdict::NotTrusted
        );
    }

    #[test]
    fn hosts_ssh_refuses_are_refused() {
        for host in [
            "", "-x", "a b", "a\tb", "a\nb", "a\u{1}b", "a,b", "a;b", "a'b", "a`b", "a\"b", "a$b",
            "a\\b", "a&b", "a<b", "a>b", "a|b", "a(b", "a)b", "a{b", "a}b",
        ] {
            assert!(!valid_ssh_host(host), "{host:?} accepted");
        }
        for host in [
            "host.example.com",
            "a-b",
            "a*b",
            "[2001:db8::1]",
            "2001:db8::1",
            "fe80::1%eth0",
            "Host_1",
        ] {
            assert!(valid_ssh_host(host), "{host:?} refused");
        }
    }

    #[tokio::test]
    async fn connect_refuses_an_invalid_host_before_any_network() {
        let config =
            SshConfig::new("a,b", "u", SshAuth::Agent).with_connect_timeout(Duration::from_secs(2));
        let err = SshPsrpTransport::connect(config).await.unwrap_err();
        assert!(err.to_string().contains("invalid SSH host"), "{err}");
    }
}
