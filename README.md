# psrp-rs

Async [PowerShell Remoting Protocol (MS-PSRP)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-psrp/)
client for Rust, built on top of [`winrm-rs`](https://crates.io/crates/winrm-rs).

`psrp-rs` layers PSRP fragments, CLIXML serialization and a runspace pool
state machine on top of `winrm-rs`, so Rust code can run PowerShell
pipelines against Windows hosts and receive **typed** results with
isolated streams.

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
- **Pure Rust** -- no C dependencies, `#![forbid(unsafe_code)]`

## Installation

```bash
cargo add psrp-rs

# For SSH transport:
cargo add psrp-rs --features ssh

# For serde support on PsValue/PsObject:
cargo add psrp-rs --features serde
```

## Usage

### Run a script and collect output

```rust,no_run
use psrp_rs::{RunspacePool, WinrmPsrpTransport};
use winrm_rs::{AuthMethod, WinrmClient, WinrmConfig, WinrmCredentials};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = WinrmClient::new(
        WinrmConfig {
            auth_method: AuthMethod::Ntlm,
            ..Default::default()
        },
        WinrmCredentials::new("administrator", "Passw0rd!", ""),
    )?;

    let transport = WinrmPsrpTransport::open(&client, "win-host.lab", &creation).await?;
    let mut pool = RunspacePool::open_with_transport(transport).await?;

    let objects = pool
        .run_script("Get-Process | Select-Object -First 5 Name, Id")
        .await?;

    for obj in objects {
        println!("{obj:?}");
    }

    pool.close().await?;
    Ok(())
}
```

### Pipeline builder with parameters

```rust,no_run
use psrp_rs::{Command, Pipeline, PsValue};
# use psrp_rs::{RunspacePool, WinrmPsrpTransport};

# async fn example(pool: &mut RunspacePool<WinrmPsrpTransport<'_>>) -> psrp_rs::Result<()> {
let result = Pipeline::empty()
    .add_command(
        Command::new("Get-Service")
            .with_parameter("Name", PsValue::String("WinRM".into()))
    )
    .add_command(
        Command::new("Select-Object")
            .with_parameter("Property", PsValue::String("Status,Name,DisplayName".into()))
    )
    .run_all_streams(pool)
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
# Ok(())
# }
```

### Capture all streams

```rust,no_run
# use psrp_rs::{Pipeline, RunspacePool, WinrmPsrpTransport};
# async fn example(pool: &mut RunspacePool<WinrmPsrpTransport<'_>>) -> psrp_rs::Result<()> {
let result = Pipeline::new("Write-Warning 'careful'; Write-Output 42")
    .run_all_streams(pool)
    .await?;

println!("Output:   {:?}", result.output);
println!("Warnings: {:?}", result.warnings);
println!("Errors:   {:?}", result.errors);
println!("Verbose:  {:?}", result.verbose);
println!("Debug:    {:?}", result.debug);
println!("Info:     {:?}", result.information);
println!("Progress: {:?}", result.progress);
# Ok(())
# }
```

### Cancel a long-running script

```rust,no_run
use tokio_util::sync::CancellationToken;
# use psrp_rs::{RunspacePool, WinrmPsrpTransport, PsrpError};

# async fn example(pool: &mut RunspacePool<WinrmPsrpTransport<'_>>) -> psrp_rs::Result<()> {
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
# Ok(())
# }
```

### Blocking API (no async runtime needed)

```rust,no_run
use psrp_rs::blocking;
use winrm_rs::{WinrmClient, WinrmConfig, WinrmCredentials};

let client = WinrmClient::new(
    WinrmConfig::default(),
    WinrmCredentials::new("admin", "password", ""),
)?;

let objects = blocking::run_script(&client, "win-host.lab", "hostname")?;
println!("{objects:?}");
# Ok::<(), Box<dyn std::error::Error>>(())
```

### SSH transport

```rust,no_run,ignore
// Requires: cargo add psrp-rs --features ssh
use psrp_rs::{RunspacePool, SshConfig, SshAuth, SshPsrpTransport};

# async fn example() -> psrp_rs::Result<()> {
let transport = SshPsrpTransport::connect(SshConfig {
    host: "win-host.lab".into(),
    port: 22,
    username: "admin".into(),
    auth: SshAuth::Password("Passw0rd!".into()),
    ..Default::default()
}).await?;

let mut pool = RunspacePool::open_with_transport(transport).await?;
let result = pool.run_script("$PSVersionTable").await?;
pool.close().await?;
# Ok(())
# }
```

### Shared pool for concurrent tasks

```rust,no_run
use psrp_rs::SharedRunspacePool;
# use psrp_rs::{RunspacePool, WinrmPsrpTransport};

# async fn example(pool: RunspacePool<WinrmPsrpTransport<'_>>) -> psrp_rs::Result<()> {
let shared = SharedRunspacePool::new(pool);

let s1 = shared.clone();
let t1 = tokio::spawn(async move {
    s1.run_script("Get-Date").await
});

let s2 = shared.clone();
let t2 = tokio::spawn(async move {
    s2.run_script("hostname").await
});

let (r1, r2) = tokio::join!(t1, t2);
shared.close().await?;
# Ok(())
# }
```

## Scope

| Feature                              | Status     |
|--------------------------------------|------------|
| Fragment encode / reassemble         | done       |
| CLIXML primitives + `<Obj>` + collections | done  |
| Runspace pool open / close           | done       |
| Pipeline builder with parameters     | done       |
| All 7 PSRP streams                   | done       |
| Typed record accessors               | done       |
| Host call dispatch                   | done       |
| Session-key cryptography             | done       |
| Command metadata (`Get-Command`)     | done       |
| Async and blocking API               | done       |
| SSH transport                        | done       |
| Shared pool (multi-task)             | done       |
| Cancellation support                 | done       |
| Pipeline input streaming             | partial    |
| Reconnect / disconnect pool          | placeholder |
| CLIXML `<Ref>` round-tripping       | read-only  |

## Cargo features

| Feature   | Default | Description                                        |
|-----------|---------|----------------------------------------------------|
| (default) | --      | WinRM transport with NTLMv2/Basic/Kerberos auth    |
| `ssh`     | no      | SSH transport via `russh`                           |
| `serde`   | no      | `Serialize`/`Deserialize` on `PsValue` / `PsObject`|

## License

Dual-licensed under **MIT** or **Apache-2.0**.
