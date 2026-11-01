# psrp-rs

Async [PowerShell Remoting Protocol (MS-PSRP)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-psrp/) client for Rust.

[![Crates.io](https://img.shields.io/crates/v/psrp-rs.svg)](https://crates.io/crates/psrp-rs)
[![docs.rs](https://img.shields.io/docsrs/psrp-rs)](https://docs.rs/psrp-rs)
[![License](https://img.shields.io/crates/l/psrp-rs.svg)](LICENSE-MIT)
[![MSRV](https://img.shields.io/badge/MSRV-1.98-blue.svg)](https://blog.rust-lang.org/)

```rust
use psrp_rs::{RunspacePool, WinrmClient, WinrmConfig, WinrmCredentials, WinrmPsrpTransport};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // HTTPS on 5986, server certificate validated. A host with only the
    // stock `Enable-PSRemoting` listener needs `WinrmConfig::http()`
    // (plain HTTP, trusted networks only).
    let client = WinrmClient::new(
        WinrmConfig::https(),
        WinrmCredentials::new("administrator", "secret", ""),
    )?;

    let (rpid, creation) = RunspacePool::<WinrmPsrpTransport>::build_creation_fragments(1, 1)?;
    let transport = WinrmPsrpTransport::open(&client, "win-server", &creation).await?;
    let mut pool = RunspacePool::open_from_transport(transport, rpid, 1, 1).await?;

    let objects = pool.run_script("Get-Process | Select-Object -First 5 Name, Id").await?;
    for obj in objects {
        println!("{obj:?}");
    }

    pool.close().await?;
    Ok(())
}
```

## Features

- **Typed PowerShell objects** -- Output stream returns `PsValue` / `PsObject` with properties, not raw strings
- **All 7 PSRP streams** -- Output, Error, Warning, Verbose, Debug, Information, Progress, each isolated
- **Pipeline builder** -- compose multi-command pipelines with named parameters, positional arguments, and switches
- **Persistent runspace pool** -- keeps a `powershell.exe` process alive across many pipelines
- **Cancellation** -- `CancellationToken`-based abort for long-running scripts
- **Session-key cryptography** -- RSA key exchange + AES-256-CBC for `SecureString` encrypt/decrypt
- **Host call dispatch** -- pluggable `PsHost` trait for interactive prompts (`Read-Host`, `Write-Host`, etc.)
- **Command metadata** -- `Get-Command` introspection via `get_command_metadata`
- **Shared pool** -- `SharedRunspacePool` for multi-task access behind `Arc<Mutex<_>>`
- **Blocking wrapper** -- synchronous API for CLI tools and scripts
- **SSH transport** -- feature-gated (`--features ssh`) alternative to WinRM via `russh`
- **Pure Rust crate** -- `#![forbid(unsafe_code)]`, no C code of its own; the only C in the dependency tree is `ring` (crypto for rustls and `russh`), which needs a C compiler but no system library

## Installation

```sh
cargo add psrp-rs

# For SSH transport:
cargo add psrp-rs --features ssh

# For serde support on PsValue/PsObject:
cargo add psrp-rs --features serde
```

`psrp-rs` re-exports the `winrm-rs` types it takes (`WinrmClient`,
`WinrmConfig`, `WinrmClientBuilder`, ...), so the common settings need no
direct dependency on `winrm-rs`. A crate that imports `winrm_rs` itself
(for `TlsProvider`, `ProxySessionAuth`, or the `kerberos` feature) must
use the same major: `winrm-rs = "2"` for `psrp-rs` 4.

### Upgrading to 4.0

`psrp-rs` 4.0 moves to `winrm-rs` 2. The main changes callers meet, all
from `winrm-rs`:

- `WinrmConfig::default()` is HTTPS on port 5986 with the certificate
  validated. `WinrmConfig::http()` is the old default (plain HTTP on 5985).
- `WinrmConfig::port` is an `Option<u16>`.
- Proxies from the environment are read only when asked for
  (`WinrmClient::builder(config).credentials(creds).use_env_proxy(true).build()`);
  the operating system's proxy settings are never read.
- Basic is refused where it would send the password in clear by accident:
  over plain HTTP unless `encryption: EncryptionMode::Never` says so, and
  with `accept_invalid_certs`. NTLM works on the same stock listener and
  seals the messages.
- The host passed to `WinrmPsrpTransport::open` and `blocking::run_*` must
  be bare and canonical: no scheme, port or `user@`, a dotted-quad IPv4
  address, an IPv6 literal in brackets and RFC 5952 form.

The full list is in [CHANGELOG.md](CHANGELOG.md) (*Upgrading from 3.x*) and
in the `winrm-rs` 2.0.0 changelog (*Upgrading from 1.x*).

## Usage

### Run a script and collect output

```rust
use psrp_rs::{
    AuthMethod, RunspacePool, WinrmClient, WinrmConfig, WinrmCredentials, WinrmPsrpTransport,
};

let client = WinrmClient::new(
    WinrmConfig {
        auth_method: AuthMethod::Ntlm,
        ..WinrmConfig::https()
    },
    WinrmCredentials::new("administrator", "Passw0rd!", "MYDOMAIN"),
)?;

let (rpid, creation) = RunspacePool::<WinrmPsrpTransport>::build_creation_fragments(1, 1)?;
let transport = WinrmPsrpTransport::open(&client, "win-server", &creation).await?;
let mut pool = RunspacePool::open_from_transport(transport, rpid, 1, 1).await?;

let objects = pool
    .run_script("Get-Process | Select-Object -First 5 Name, Id")
    .await?;

for obj in objects {
    println!("{obj:?}");
}

pool.close().await?;
```

### Pipeline builder with parameters

```rust
use psrp_rs::{Command, Pipeline, PsValue};

let result = Pipeline::empty()
    .add_command(
        Command::new("Get-Service")
            .with_parameter("Name", PsValue::String("WinRM".into()))
    )
    .add_command(
        Command::new("Select-Object")
            .with_parameter("Property", PsValue::String("Status,Name,DisplayName".into()))
    )
    .run_all_streams(&mut pool)
    .await?;

for obj in &result.output {
    println!("{obj:?}");
}
for err in result.typed_errors() {
    eprintln!("ERROR: {:?}", err.exception);
}
for warn in result.typed_warnings() {
    eprintln!("WARN: {}", warn.message);
}
```

### Capture all streams

```rust
use psrp_rs::Pipeline;

let result = Pipeline::new("Write-Warning 'careful'; Write-Output 42")
    .run_all_streams(&mut pool)
    .await?;

println!("Output:   {:?}", result.output);
println!("Warnings: {:?}", result.warnings);
println!("Errors:   {:?}", result.errors);
println!("Verbose:  {:?}", result.verbose);
println!("Debug:    {:?}", result.debug);
println!("Info:     {:?}", result.information);
println!("Progress: {:?}", result.progress);
```

### Cancel a long-running script

```rust
use tokio_util::sync::CancellationToken;
use psrp_rs::PsrpError;

let cancel = CancellationToken::new();
let token = cancel.clone();

tokio::spawn(async move {
    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    token.cancel();
});

match pool.run_script_with_cancel("Start-Sleep -Seconds 300", cancel).await {
    Err(PsrpError::Cancelled) => println!("Script was cancelled"),
    other => println!("{other:?}"),
}
```

### Blocking API

```rust
use psrp_rs::{WinrmClient, WinrmConfig, WinrmCredentials, blocking};

let client = WinrmClient::new(
    WinrmConfig::https(),
    WinrmCredentials::new("admin", "password", ""),
)?;

let objects = blocking::run_script(&client, "win-server", "hostname")?;
println!("{objects:?}");
```

### SSH transport

```rust
// Requires: cargo add psrp-rs --features ssh
use psrp_rs::{RunspacePool, SshConfig, SshAuth, SshPsrpTransport};

// Host-key validation defaults to ~/.ssh/known_hosts (fail-closed).
let config = SshConfig::new("win-server", "admin", SshAuth::Password("Passw0rd!".into()))
    .with_port(22);
let transport = SshPsrpTransport::connect(config).await?;

let mut pool = RunspacePool::open_with_transport(transport).await?;
let result = pool.run_script("$PSVersionTable").await?;
pool.close().await?;
```

The transport speaks PowerShell's out-of-process protocol over the SSH
`powershell` subsystem, the one `pwsh -sshs` serves. The server needs:

- PowerShell 7 or later;
- a subsystem line in `sshd_config`, with a path that holds no space:

  ```text
  Subsystem powershell /usr/bin/pwsh -sshs -NoLogo
  ```

  On Windows use the short (8.3) path of `pwsh.exe`, for example
  `Subsystem powershell C:/PROGRA~1/POWERS~1/7/pwsh.exe -sshs -NoLogo`;
- on Linux, a login shell that writes nothing to stdout (no banner, no
  `echo` in a profile): any non-XML line there is rejected.

See the [`psrp_rs::ssh` documentation](https://docs.rs/psrp-rs/latest/psrp_rs/ssh/index.html)
for the protocol and the host-key policies.

### Shared pool for concurrent tasks

```rust
use psrp_rs::SharedRunspacePool;

let shared = SharedRunspacePool::new(pool);

let s1 = shared.clone();
let t1 = tokio::spawn(async move { s1.run_script("Get-Date").await });

let s2 = shared.clone();
let t2 = tokio::spawn(async move { s2.run_script("hostname").await });

let (r1, r2) = tokio::join!(t1, t2);
shared.close().await?;
```

## Configuration

`psrp-rs` reuses [`WinrmConfig`](https://docs.rs/winrm-rs/2/winrm_rs/struct.WinrmConfig.html)
from `winrm-rs` 2 for transport-level settings (auth method, TLS, timeouts, proxy).
See the [winrm-rs documentation](https://docs.rs/winrm-rs/2) for the full list of config fields.
The defaults that matter most:

- **TLS.** `WinrmConfig::default()` and `WinrmConfig::https()` connect over
  HTTPS on 5986 and validate the server certificate against the built-in
  Mozilla roots, which a listener certificate issued by an internal CA (AD
  CS, the usual case for WinRM) does not chain to. Build the client with
  `WinrmClient::builder(config).credentials(creds)`, then
  `.platform_roots(true)` (the operating system's store),
  `.add_root_certificates_pem(..)` or `.pin_server_certificate_sha256(..)`,
  and `.build()`. `accept_invalid_certs` is for disposable test hosts only.
  `WinrmConfig::http()` is plain HTTP on 5985: NTLM still seals the
  messages there, but its handshake can be relayed, or recorded to guess
  the password offline; trusted networks only.
- **Port.** `port: None` means 5986 with TLS and 5985 without;
  `effective_port()` returns the port in use.
- **Proxy.** Proxies from the environment are read only by a client built
  with `.use_env_proxy(true)`; the operating system's proxy settings are
  never read. An explicit `proxy` is a `SecretString`.
- **Basic.** Over plain HTTP it needs `encryption: EncryptionMode::Never`, and
  the password and every SOAP body then cross in clear; with
  `accept_invalid_certs` it is refused. Prefer NTLM, or Basic over HTTPS
  with a validated or pinned certificate.
- **Limits.** `WinrmConfig::max_output_bytes` does not bound PSRP: a
  pipeline's output is collected by psrp-rs, not by winrm-rs's
  `run_command`.

Pool-level parameters:

| Parameter | Default | Description |
|---|---|---|
| `min_runspaces` | `1` | Minimum number of runspaces the server should maintain |
| `max_runspaces` | `1` | Maximum concurrent runspaces (controls server-side parallelism) |

Set via `RunspacePool::open_with_options(transport, min, max)` or
`build_creation_fragments(min, max)` + `open_from_transport(...)`.

## Roadmap

| Version | Milestone | Status |
|---|---|---|
| **v1.0** | Full PSRP: CLIXML, fragments, runspace pool, pipeline builder, all 7 streams, typed records, host calls, session-key crypto, SSH transport, blocking API, shared pool, cancellation | **Current** |
| **v1.x** | Pipeline input streaming, disconnect/reconnect pool, CLIXML `<Ref>` round-tripping | Planned |

## Comparison

| | **psrp-rs** | **pypsrp** (Python) | **PowerShell SDK** (.NET) |
|---|---|---|---|
| Language | Rust | Python | C# |
| Async | native async/await | no | `Task`-based |
| Typed output | `PsValue` / `PsObject` | dict-based | `PSObject` |
| All 7 streams | yes | yes | yes |
| Pipeline builder | yes | yes | yes |
| Host callbacks | pluggable `PsHost` trait | no | `PSHost` |
| Session-key crypto | RSA + AES (pure Rust) | yes | built-in |
| SSH transport | `russh` (feature-gated) | yes | built-in |
| Auth methods | NTLMv2, Basic, Certificate (via winrm-rs); Kerberos with `winrm-rs`'s `kerberos` feature | NTLM, Basic, Kerberos, CredSSP | all |
| TLS backend | rustls (`ring`, private to the client unless the application installed a provider) | OpenSSL | SChannel / OpenSSL |
| Binary size | single static binary | interpreter | runtime |
| C dependencies | `ring` only (transitive, no system library) | OpenSSL | CLR |

## Contributing

Contributions are welcome. Please open an issue to discuss larger changes before submitting a PR.

```sh
cargo test --all-features      # unit + end-to-end tests (no network)
cargo clippy --all-targets --all-features
cargo fmt --all --check
cargo deny check               # advisories + licences
MODE=smoke ./fuzz/run.sh       # quick pass over every fuzz target
```

## Integration tests

Unit tests and end-to-end tests run against a mock transport and need no
external setup. The file [`tests/integration_real.rs`](tests/integration_real.rs)
targets a real Windows host and is ignored by default. To run it, set the
following environment variables and use `--ignored`:

| Variable | Required | Default | Description |
|---|---|---|---|
| `PSRP_INTEGRATION_HOST` | yes | -- | Bare hostname or IP of the target Windows box (no scheme, port or `user@`) |
| `PSRP_INTEGRATION_USER` | no | `vagrant` | Username |
| `PSRP_INTEGRATION_PASS` | no | `vagrant` | Password |
| `PSRP_INTEGRATION_TLS` | no | off | `1` or `true` for HTTPS on 5986 (self-signed certificate accepted) |
| `PSRP_INTEGRATION_PORT` | no | 5985, or 5986 with TLS | Port override |
| `PSRP_INTEGRATION_AUTH` | no | NTLM | `basic` for Basic over plain HTTP, message encryption off |

A [`Vagrantfile`](Vagrantfile) is provided to spin up a disposable Windows
Server 2025 Hyper-V VM with WinRM + PSRP pre-configured:

```sh
vagrant.exe up --provider=hyperv
vagrant.exe ssh -c "ipconfig"     # grab the VM IP

PSRP_INTEGRATION_HOST=<ip> \
PSRP_INTEGRATION_USER=vagrant \
PSRP_INTEGRATION_PASS=vagrant \
  cargo test --test integration_real -- --ignored
```

## Fuzzing

Everything this crate parses comes from the remote host, so the decoders are
fuzzed continuously. Seventeen [`cargo-fuzz`](https://github.com/rust-fuzz/cargo-fuzz)
targets live under [`fuzz/fuzz_targets/`](fuzz/fuzz_targets/), covering the
fragment reassembler, the PSRP message header, the CLIXML parser and encoder,
the typed record decoders, the host-call dispatcher, the session-key crypto,
the runspace state machine, the async pool driven over a mock transport, the
SSH `known_hosts` matcher and the SSH OutOfProc line codec.

```sh
rustup toolchain install nightly
cargo install cargo-fuzz

./fuzz/run.sh                           # every target, 60s each
DURATION=900 ./fuzz/run.sh              # 15 minutes per target
TARGETS="clixml_decoder" ./fuzz/run.sh  # just one
./fuzz/coverage.sh                      # what the corpora actually reach
```

Beyond "does not panic", the round-trip targets assert real protocol
properties: reassembly must not depend on how the bytes were chunked, the
.NET mixed-endian GUIDs must survive the header, the CLIXML codec must reach a
fixed point, a closed or broken runspace pool must never return to `Opened`,
and decrypting with the wrong session key must never yield the right
plaintext.

This work found and fixed seven defects, including two remote denials of
service. The CLIXML parser was recursive with no depth limit, so about 10 KiB
of nested `<Obj>` from a hostile server overflowed the stack and aborted the
process — parsing depth is now capped by
[`MAX_NESTING_DEPTH`](https://docs.rs/psrp-rs/latest/psrp_rs/constant.MAX_NESTING_DEPTH.html).
And the SSH `known_hosts` glob matcher backtracked exponentially, so a pattern
such as `*a*a*a*a*b` against a long hostname hung host-key verification
itself; it is now an iterative `O(n*m)` matcher.

## Cargo features

| Feature | Default | Description |
|---|---|---|
| *(default)* | -- | WinRM transport with NTLMv2/Basic/Certificate auth (via winrm-rs). For Kerberos, also depend on `winrm-rs = { version = "2", features = ["kerberos"] }` |
| `ssh` | no | SSH transport via `russh`, speaking PowerShell's out-of-process protocol (`pwsh -sshs`, PowerShell 7+) |
| `serde` | no | `Serialize`/`Deserialize` derives on `PsValue` / `PsObject` |

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT License](LICENSE-MIT) at your option.
