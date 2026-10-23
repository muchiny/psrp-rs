# Changelog

All notable changes to `psrp-rs` are documented in this file. The format
is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- **`SshConfig::with_ack_timeout`** sets how long to wait for `pwsh` to
  acknowledge a request over SSH (default 60 s, as before). `pwsh`
  acknowledges the runspace pool's first message only once the pool is
  built, which a heavy session configuration, an antivirus scan on a cold
  start or an overloaded host can delay past 60 s; the error for that
  request now names the setting. A zero timeout is refused by
  `SshPsrpTransport::connect`.

### Changed

- **`sha1` 0.10 and `rsa`'s `sha1` feature are gone from the dependency
  tree.** The session-key exchange has been RSAES-PKCS1-v1_5 since 3.0.0,
  which takes no hash, so `psrp-rs` no longer needed them. The tree also
  loses `block-buffer` 0.10 and `cpufeatures` 0.2. No API or behaviour
  change; the `ssh` feature keeps `sha1` 0.11 for hashed `known_hosts`
  entries.

### Fixed

- **Cancelling a pipeline over WinRM no longer loses the server's reply.** A
  WS-Man Receive is a long poll, and dropping it (which `run_with_cancel`
  does when the token fires) closes the connection and discards whatever
  the server had produced for it. `WinrmPsrpTransport` now keeps the Receive
  in flight and resumes it on the next read, so a cancelled `recv_chunk`
  loses nothing. Once the stop signal has been accepted, the server deletes
  the command and answers that Receive with `InvalidSelectors` instead of a
  final `Stopped` (the same fault also means "the shell is gone", which the
  next command then reports); it is now read as the end of the stop, and
  `run_with_cancel` returns `Cancelled` with the pool usable, instead of a
  SOAP error. **The stop signal itself needs `winrm-rs` 1.4.1**: 1.4.0 and
  earlier addressed a PSRP shell with the `cmd` `ResourceURI` and code, so
  the server refused it (#35); with them, cancelling over WinRM still fails
  at the signal.
- **The value of a .NET enum is no longer dropped.** PowerShell writes an
  enum as an `<Obj>` with its type names, a `<ToString>` and the number as
  a nameless child (`<I32>1</I32>`); the decoder skipped that child, so every
  enum in a result (`[DayOfWeek]::Friday`, a `PriorityClass`, the
  `CommandOrigin` of an `InvocationInfo`) arrived as an object with no value.
  The number is now under the `_value` property, as a bare `<LST>` or
  `<DCT>` already was. The method id of a host call is an enum, so a host
  call whose `mi` came this way failed with `host call: missing mi`; it is
  read from `_value` now.
- **`PipelineFailed` says why the pipeline failed.** A terminating error
  (`throw`, a cmdlet run with `-ErrorAction Stop`, `1/0`) is reported in the
  `PipelineState` message, which was never read, so the error was always
  "unknown error". It now carries the exception message the server
  attached. When the error stream also held `ErrorRecord`s, their text was
  a dump of the whole record several KiB long; it is now the exception
  message. What the server wrote is escaped (control and bidi characters)
  and bounded: 1024 characters per error, at most 8 errors quoted and the
  rest counted, and the same goes for the text of every CLIXML parse error,
  which can quote the document.
- **`RunspacePoolStateMachine::open` is accepted from `BeforeOpen` only.**
  It refused a closed or broken pool, but from `Closing`, `Opened` or
  `Disconnected` it reset the machine to `NegotiationSent` and sent the
  handshake again, so `close` then `open` let the server drive the pool back
  to `Opened`. PowerShell refuses it too (`CannotOpenAgain`). `RunspacePool`
  was not affected (it opens a fresh machine); only code driving the public
  state machine directly was.
- **Base64 is read the way .NET reads it, and malformed input is refused.**
  The decoder behind `<BA>`, the public key, the encrypted session key and
  the SSH `<Data>` packets cut the text at the first `=`, accepted a missing
  or incomplete padding, a length that is not a multiple of four and any
  Unicode whitespace, so `AA==!!junk` and `Zg` decoded to `[0]` and `[102]`
  where `Convert.FromBase64String` throws. It now accepts exactly what .NET
  does: only space, tab, CR and LF are skipped, the length is a multiple of
  four, and at most two `=` close the text. A payload that PowerShell would
  refuse is an error instead of being silently truncated; PowerShell writes
  canonical base64, so nothing it sends changes.
- **A `SecureString` answered to a host call is encrypted, never sent as
  plaintext.** What a `PsHost` returns for `Read-Host -AsSecureString` or
  `Get-Credential` crossed the wire as `<SS>plaintext</SS>`, which
  PowerShell cannot decrypt, and the password travelled in clear at the PSRP
  layer. The host still returns the plaintext; the pool now encrypts it with
  the session key (AES-256-CBC, base64, as `encrypt_secure_string`). With no
  key yet it starts the key exchange itself and sends the answer when the
  key arrives (or answers the host call with an error if the key cannot be
  taken), and it answers the server's `PublicKeyRequest`, which used to be
  ignored. The `EncryptedSessionKey` is now taken
  by whichever call reads it, not only by `request_session_key`, so a key
  that arrives while a pipeline runs is no longer lost. Host calls still
  waiting for a key are not carried over `disconnect`/`reconnect`. Not yet
  reachable against PowerShell: psrp-rs declares a null host and its
  host-method ids do not match PowerShell's, so a real server does not make
  these calls yet (tracked in #52); the encryption and the key handling are
  tested against the mock transport.

## [3.1.0] — 2026-10-23

Eight defects of the CLIXML codec and the session-key exchange, each found
by comparing psrp-rs with PowerShell's own serializer (most of them live,
on Windows Server 2025 and pwsh 7.6.7). Some change what goes on the wire:
a carriage return is now escaped, a script block is `<SBK>`, and a
SecureString is encrypted with a zero IV and no prefix, so a SecureString
ciphertext written by 3.0.0 or earlier no longer decrypts correctly.

### Fixed

- **A `[char]` that is half of a surrogate pair no longer fails the whole
  pipeline.** PowerShell sends a `[char]` as its UTF-16 unit, so
  `"😀".ToCharArray()` is `<C>55357</C><C>56832</C>`; the decoder rejected a
  surrogate and the error discarded everything collected so far. Each one is
  now `PsValue::Char('\u{FFFD}')`. In the other direction a `PsValue::Char`
  outside the Basic Multilingual Plane was written as `<C>128512</C>`, which
  PowerShell refuses (the whole message fails); it is now written as
  U+FFFD. A `<C>` above 65535, which only older psrp-rs wrote, is still read
  as that character. `PsValue::Char` keeps its type; use a string to carry
  text.
- **`RunspacePool::request_session_key` no longer waits forever when the
  server breaks the pool.** The exchange skipped every message except
  `EncryptedSessionKey`, including a `RunspacePoolState` saying `Broken` or
  `Closed`, so a server that rejected the key left the call polling (about
  40 s, then a timeout, over WinRM). It now fails at once with a
  `PsrpError::Protocol`, and the terminal-state error, here and when a
  server breaks a pool that is opening, carries the server's reason (the
  exception message of the state message's error record), truncated to 1024
  characters with control and bidi characters escaped. There is still no
  timeout on the exchange: over WinRM a receive cannot be cancelled safely,
  so close the pool after giving up on it.
- **A carriage return in a string sent to PowerShell is no longer turned
  into a line feed.** PowerShell's XML reader normalises line endings in
  element text, so `"a\r\nb"` arrived as `"a\nb"`. The encoder now writes
  a CR in element text as `_x000D_`, as PowerShell's own serializer does
  (tab and line feed stay literal in text). A script read from a CRLF file
  now reaches PowerShell with its CRs, and each CR costs 7 bytes more on
  the wire.
- **Characters outside the Basic Multilingual Plane come back as one
  character.** PowerShell writes them as two escapes of their UTF-16
  surrogates (`_xD83D__xDE00_` for an emoji); the decoder left that text
  literal. A pair now decodes to the character, and a lone surrogate to
  U+FFFD.
- **Script blocks use the tag PowerShell uses, `<SBK>`.** psrp-rs wrote and
  read `<SCT>`, which PowerShell does not know: a script block in a server's
  output was dropped without any error (a property missing, a list item
  gone, shifting the ones after it), and one sent to a server made it
  reject the whole message. It now writes `<SBK>` and reads both tags. The
  server receives the body as a plain string (remoting never turns it back
  into a script block), so a `[scriptblock]` parameter needs
  `[scriptblock]::Create($s)`.
- **An empty string or script block written self-closed is no longer
  lost.** PowerShell normally writes an empty value as `<S N="x" />`; in an
  object's properties it was dropped (so `get("x")` was `None`) and in a
  dictionary it was read as `Null`. It is now an empty string.
- **SecureStrings use PowerShell's zero IV.** `encrypt_secure_string` put a
  random IV in front of the ciphertext and `decrypt_secure_string` took the
  first 16 bytes for the IV, but PowerShell uses a zero IV and no prefix: a
  server decrypting our SecureString got 8 garbage characters before the
  text, and we lost the first 8 characters of the server's (a one-block
  secret was rejected as malformed). Both directions now match PowerShell
  (checked live against pwsh 7.6.7 over SSH and Windows PowerShell 5.1 over
  WinRM). The ciphertext is now deterministic for a given session key, as
  the protocol requires, and a ciphertext written by an older psrp-rs (with
  its IV prefix) no longer decrypts correctly. The codec still does not
  encrypt a `PsValue::SecureString` by itself, and the SecureStrings that a
  `PsHost` answers to `Read-Host -AsSecureString` and `Get-Credential` still
  travel in clear (tracked in #36).
- **A repeated object is no longer lost from a list or a dictionary.**
  PowerShell writes the second occurrence of an object in one graph
  (`@($o, $o)`, `@{a=$o; b=$o}`) as a self-closed `<Ref RefId="…" />`. The
  decoder dropped it from a list, so the items after it moved up, and read
  it as `Null` in a dictionary. It is now resolved wherever it appears (list
  item, dictionary key or value, property, top level). A reference to an
  object that is not decoded yet (dangling, or back to an object still being
  built) is `Null` in its place, as it already was in a property. The copies
  a document may make are bounded, by a budget that grows with its size: a
  server could chain objects that each hold two references to the previous
  one, and ~1 KiB of XML expanded to 2^n values and aborted the process out
  of memory (properties already took that path). Going over the budget, or
  a reference that would nest deeper than `MAX_NESTING_DEPTH`, is now a
  parse error. Only objects that a `<Ref>` points to are kept for it.

## [3.0.0] — 2026-10-23

SSH host-key checks now follow OpenSSH: several `known_hosts` lines that
OpenSSH applies, revocations among them, were ignored. The SSH password
and key passphrase are kept in `SecretString`s, which breaks code that
builds `SshAuth` from a `String`; `ClientSessionKey::public_blob_hex` is
deprecated. The SSH transport did not work against PowerShell: it wrote raw
PSRP fragments to the `powershell` subsystem, which `pwsh -sshs` does not
read that way. It now speaks PowerShell's out-of-process protocol. The
`SecureString` session-key exchange used hex and RSA-OAEP where MS-PSRP
specifies base64 and RSAES-PKCS1-v1_5; it now follows the specification.
`winrm-rs` 1.3.0 or later is now required.

### Upgrading from 2.x

- `SshAuth::Password` and `SshAuth::PrivateKey::passphrase` take a
  `SecretString`: pass a `String` with `.into()` (a `&str` literal with
  `.into()` already compiles), and read one back with `expose_secret()`
  (`ExposeSecret` is re-exported from `psrp_rs::ssh`).
- `SshPsrpTransport::connect` refuses a host ssh(1) refuses (see
  Security), before any network access.
- The SSH server needs PowerShell 7 or later and a
  `Subsystem powershell <path without space>/pwsh -sshs -NoLogo` line in
  `sshd_config` (on Windows, the short 8.3 path); see the `psrp_rs::ssh`
  documentation.
- `ClientSessionKey::public_blob_hex` is deprecated: use
  `public_blob_base64`. `ClientSessionKey::decrypt_session_key` now takes
  the base64-decoded `SIMPLEBLOB` of the `EncryptedSessionKey` message,
  not a bare RSA ciphertext. `RunspacePool::request_session_key` needs no
  change.
- A hand-written `[host]:22` line in `known_hosts` no longer matches;
  write `host`.
- Through `winrm-rs` 1.3: NTLM over HTTP now seals every message and
  fails closed (`WinrmError::Ntlm`, the pool has to be reopened), and
  Kerberos under `EncryptionMode::Auto` seals over HTTP (a realm with RC4
  keys only needs `EncryptionMode::Never`).
- A `PsrpTransport` that wraps or forwards to another one must forward the
  new `send_pipeline_fragment` too: its default goes through
  `send_fragment`, to the pool, so around `SshPsrpTransport` every pipeline
  message would go out on `Guid.Empty`.

### Changed

- **`winrm-rs` requirement raised to `"1.3.0"`** (from `"1.2.2"`). Under
  1.2.x, NTLM message sealing never worked: with the default
  `EncryptionMode::Auto` over HTTP, the first SOAP body rode on the
  handshake in plaintext and every later one, refused by the server once
  sealed, was re-sent in plaintext. 1.3.0 seals every request and fails
  closed. It also builds TLS on `ring` only, so `aws-lc-sys` and its CMake
  build are gone from the tree. No `psrp-rs` code changed; the PSRP shell
  calls (`open_psrp_shell`, `reconnect_shell`, the SOAP envelopes) are
  identical. What callers can see through `psrp-rs` (the `winrm-rs` 1.3.0
  changelog has the full list):
  - an HTTP 401 or an unsealed answer to a sealed NTLM request is
    `WinrmError::Ntlm`; the request is not re-sent and the pool has to be
    reopened;
  - with the `winrm-rs` `kerberos` feature, `EncryptionMode::Auto` now seals
    over HTTP; a realm that only has RC4 keys needs `EncryptionMode::Never`;
  - `AuthMethod::Certificate` with `use_tls = false` fails when the
    `WinrmClient` is built;
  - a response body over `4 * max(max_envelope_size, 512 KiB)` (2 MiB by
    default) is `SoapError::ParseError`.
- **`russh` 0.63 → 0.64** (`ssh` feature), built with
  `default-features = false, features = ["ring", "rsa", "flate2"]`: the
  features of russh's default set, with `ring` in place of `aws-lc-rs`, so
  the `ssh` feature brings no `aws-lc-sys` either. **`hmac` 0.12 → 0.13**;
  the HMAC-SHA1 of hashed `known_hosts` entries now runs on `sha1` 0.11
  (renamed `sha1_hmac` in `Cargo.toml`). No API change. The `sha1` 0.10
  dependency and the `sha1` feature of `rsa` were only there for the
  RSA-OAEP session-key exchange; that exchange is RSAES-PKCS1-v1_5 now
  (see Fixed), no code in `psrp-rs` uses either any more, and a follow-up
  will remove them.
- **`PsrpTransport::send_pipeline_fragment`** is a new method, with a
  default implementation that forwards to `send_fragment`: existing
  implementations compile and behave as before. The runspace pool calls it
  for every message addressed to a pipeline, passing the pipeline id, so a
  transport that multiplexes by pipeline (the SSH one) can route it.
- **`ClientSessionKey::decrypt_session_key`** unwraps the RSA block with a
  blinded operation, and reports every failure after the `SIMPLEBLOB`
  checks (bad padding, wrong key length) with the one message
  `session key unwrap failed`, so the error does not tell a padding
  failure from a length failure.
- **`RunspacePool::close` over SSH returns the error when the session had
  already broken** (the server died, an acknowledgement timed out), where
  it used to return `Ok`. The SSH channel and connection are torn down
  either way.
- **Over SSH, a request abandoned mid-write or between two `<Data>` lines
  breaks the session.** A future dropped (by a timeout or `select!`) while
  a line was being written, or before the last `<Data>` line of a message
  above 32 KiB was acknowledged, could leave a partial line or a partial
  PSRP fragment on the server: the next operation now fails with a
  protocol error and writes nothing, and the pool has to be reopened.
  `signal_stop` after such a drop (as `Pipeline::run_with_cancel` sends
  it) may then report that protocol error instead of `Cancelled`.

### Added

- `ClientSessionKey::public_blob` (the raw `PUBLICKEYBLOB` bytes) and
  `ClientSessionKey::public_blob_base64` (the `PublicKey` text MS-PSRP
  2.2.2.3 sends).
- The `out_of_proc_lines` fuzz target (seventeen targets now) for the
  line codec of the out-of-process protocol, with a seed corpus and a
  dictionary.

### Fixed

- **The SSH transport did not work against PowerShell.** It wrote raw PSRP
  fragments to the `powershell` subsystem, while `pwsh -sshs` speaks the
  out-of-process protocol: one XML element per line, PSRP fragments
  base64-encoded in `<Data>` lines. The transport now speaks it, with an
  acknowledgement awaited for every packet before the next is sent and a
  `<Command/>` for each pipeline. Checked against Windows Server 2025 with
  PowerShell 7.6.7.
- **`signal_stop` over SSH stops the pipeline.** It used to log a warning
  and do nothing; it now sends `<Signal/>`.
- **A closed SSH channel or a dead `pwsh` is an error, not a hang.** The
  error carries the message the server wrote
  (`__NamedPipeError__:<message>`) when there is one.
- **`SshPsrpTransport::connect` reports a refused subsystem** ("SSH server
  refused the 'powershell' subsystem"), and a channel closed before the
  subsystem started, as errors; it did not wait for the server's reply.
- **`get_command_metadata` works over SSH.**
- **The `SecureString` session-key exchange never completed against a real
  server.** `RunspacePool::request_session_key` sent the public key as hex
  and expected the session key as hex wrapped with RSA-OAEP. MS-PSRP
  (2.2.2.3 and 2.2.2.4) specifies base64 in both directions, and the
  server's answer is a CryptoAPI `SIMPLEBLOB` (a 12-byte header and the
  AES key under RSAES-PKCS1-v1_5, little-endian). A real server answered
  `Invalid public key data.` over SSH, and the WinRM call timed out. The
  exchange now follows the specification and works over SSH and WinRM.
- **A broken or closed runspace pool could be brought back to `Opened`.**
  `RunspacePoolStateMachine::close` overwrote a terminal `Broken` or
  `Closed` state with `Closing`, so a later `open` restarted the handshake
  and a server message could reopen the pool. `close` now leaves a terminal
  pool untouched and sends no `CloseRunspacePool`.
  Found by the nightly `runspace_state_machine` fuzz run.
- **The CLIXML encoder corrupted some strings on the wire.** It left a `_`
  literal unless a complete `_xHHHH_` followed, but the escape it wrote for
  the next character could itself complete a false sequence: a property
  name `_x0041` followed by a carriage return arrived as `"Ax000D_"`, and a
  literal `_X0041_` arrived as `"A"` on a real PowerShell server. Every `_`
  followed by `x` or `X` is now written `_x005F_`, which is exactly what
  PowerShell's own serializer does (`InternalSerializer.EncodeString`), so
  text such as `$my_xml` is sent as `$my_x005F_xml`. Found by the nightly
  `clixml_roundtrip` fuzz run.

### Security

- **`known_hosts` lookups did not follow OpenSSH, and most of the
  differences let a revoked key through** (`ssh` feature,
  `HostKeyPolicy::KnownHosts`). ssh(1) looks a host up under one name (the
  host as `ssh -G` prints it on port 22, `[host]:port` on any other port),
  matches every pattern, plain or hashed, against that name, and compares
  keys without their comment. `psrp-rs` instead:
  - compared keys with their comment, so a line copied from a `.pub` file
    (`@revoked * KEY user@host`) revoked nothing, and a trusted line with a
    comment trusted nothing;
  - skipped as malformed any line whose fields were separated by a tab,
    several spaces or leading spaces, `@revoked` lines included;
  - compared hashed entries (`|1|salt|hash`, what `ssh-keygen -H` and
    `HashKnownHosts yes` write) with the bare host name whatever the port:
    an entry recorded for port 22 was trusted on every port of the host,
    one recorded for another port never matched, and an `@revoked` hashed
    line for another port was never applied;
  - matched a pattern without a port on port 22 only, so `@revoked * KEY`
    (the sshd(8) example) revoked nothing on any other port, and
    `[host]:*` never matched;
  - hashed the host name as given, so `Host.Example.COM` missed the hashed
    entries for `host.example.com`, `@revoked` lines included, while plain
    patterns ignored case;
  - looked numeric addresses up as written, so a connection to `127.1` or
    `2001:db8:0:0::1` missed `@revoked 127.0.0.1` or `@revoked 2001:db8::1`
    (now canonical, `inet_aton` forms included: `0x7f.1`, `017.0.0.1`);
  - honoured a hashed entry whose salt is not 20 bytes, a line OpenSSH
    refuses.

  Lookups now follow OpenSSH 10.0, checked against lines produced by
  `ssh-keygen -H` and the host names `ssh -G` prints. One visible
  tightening: a hand-written `[host]:22` entry no longer matches, since
  ssh(1) never looks that name up; write `host` instead. Two differences
  remain, on purpose: nothing is retried under the bare name when no entry
  matches `[host]:port` (ssh(1) does in some setups; refusing is the safe
  side), and a pattern of 1023 bytes or more is honoured (OpenSSH ignores
  the whole line, `@revoked` included). The `known_hosts_match` fuzz
  target now drives the whole lookup, with keys stripped of their comment
  as a server presents them, and asserts that `@revoked * KEY comment`
  revokes the key for any host and port and that the verdict depends
  neither on the case of the host name nor on how fields are spaced. The
  comment and spacing assertions were checked the other way round: each
  fails within a minute once its fix is undone.
- **`SshPsrpTransport::connect` refuses a host ssh(1) refuses**: empty,
  starting with `-`, or holding whitespace, a control character or one of
  ``'`"$\;&<>|(){},`` (what `ssh -G` reports as "hostname contains invalid
  characters"). Such a host used to reach the resolver and the logs, where
  a newline in it could forge a log line, and a `known_hosts` lookup,
  where `,` is the list separator.
- **Breaking: `SshAuth` keeps the SSH password and key passphrase in
  `SecretString`s.** `SshAuth::Password` and
  `SshAuth::PrivateKey::passphrase` now hold a `SecretString` (from
  `secrecy` 0.10, as in `winrm-rs`'s credentials, and re-exported with
  `ExposeSecret` as `psrp_rs::ssh::{SecretString, ExposeSecret}`) instead
  of a `String`. The copy each `SshAuth` and each of its clones holds is
  zeroized when dropped; before, every copy stayed in freed memory. Not
  covered: the value the caller builds it from (converting a `String` with
  spare capacity reallocates it and leaves the old buffer as it was), and
  the copies russh's key loader makes; russh wipes the copy of the
  password it sends. `SshAuth::Password("…".into())` still compiles; a
  `String` now takes `.into()`, and reading a secret back takes
  `expose_secret()`.
- **`SshAuth`'s `Debug` printed the password and the key passphrase**, and
  so did `SshConfig`'s, which derives `Debug`: logging a configuration with
  `{:?}` leaked the secret. Both now show `<redacted>`; the key path is
  still printed.
- **The SSH transport bounds what a hostile server can cost.** A line
  trickled in one byte per packet, an element with ~100k attributes or a
  flood of one-byte `<Data>` lines costs linear CPU and bounded memory;
  `connect` buffers at most 1 MiB of output before the subsystem reply,
  then fails with "SSH server sent unexpected output before the subsystem
  replied"; and the text the server controls (its `__NamedPipeError__:`
  message, sshd's stderr in the debug log, a host certificate's key id in
  a warning) is truncated, its control and bidi characters escaped.

### Known

- `psrp_rs::blocking` drives the pool on a current-thread Tokio runtime.
  `winrm-rs` 1.3.0 documents a race on its dedicated sealed connections
  (NTLM or Kerberos over HTTP, measured against a server with
  `AllowUnencrypted = false`) that it mitigates on such a runtime but does
  not close. When it hits, the call fails with an HTTP 401 error; the
  request is never re-sent in plaintext. Not reproduced with `psrp-rs`.

## [2.0.2] — 2026-09-04

Disconnect/reconnect now works against a live server. It never did before —
the path was only ever exercised by `MockTransport`. Requires `winrm-rs`
1.2.2, which makes the underlying WinRM shell disconnectable.

### Fixed

- **Reconnect replayed the PSRP handshake and then timed out.**
  `DisconnectedPool::reconnect` re-sent `SessionCapability` +
  `ConnectRunspacePool` and waited for a fresh `RunspacePoolState=Opened`,
  but after an existing-client WSMan `Reconnect` — same `SessionId`, so the
  server keeps the runspace `Opened` — there was nothing more for the server
  to send, and the follow-up Receive died with `w:TimedOut`. Reconnect now
  resumes straight to `Opened` with no PSRP message, matching pypsrp's
  `_connect_existing_client`. The state machine only resumes a genuinely
  resumable pool (`BeforeOpen` or `Disconnected`); a fuzz run caught the
  first cut resurrecting a closed pool into `Opened`, so the guard is now
  explicit. Verified live on Server 2025: open, run, disconnect, reconnect,
  run again, close. (`src/runspace/pool.rs`, `src/runspace/state.rs`)

## [2.0.1] — 2026-09-04

A shell-lifecycle leak, found by running the crate against live Windows
hosts — Server 2012 R2 and Server 2025 — rather than by reading it. It pairs
with the two leaks fixed in `winrm-rs` 1.2.1, which this release now
requires: without that one, closing a PSRP pool addressed the Delete to the
`cmd` plugin, the server answered `InvalidSelectors: the shell was not
found`, and the runspace kept running.

### Fixed

- **A failed `RunspacePool::disconnect` abandoned the runspace.**
  `disconnect` takes `self`, so an error from the transport destroyed the
  pool — and with it the caller's only handle to a runspace that was still
  live on the server. The WinRS PowerShell plugin rejects Disconnect on both
  Server 2012 R2 and Server 2025, so every attempt leaked one runspace
  against `MaxShellsPerUser` (30 by default), after which every new pool
  failed to open with `InternalError`. The shell is now closed through the
  transport before the original error is surfaced.
  (`src/runspace/pool.rs`)

### Changed

- **`winrm-rs` requirement raised to `"1.2.1"`** (from `"1.2"`). 1.2.1 is
  what makes `Shell::close` address Delete under the shell's own
  ResourceURI, which is the other half of the leak above.

### Known

- `live_disconnect_reconnect_pool` still exercises nothing on a real server.
  Server 2025 refuses the Disconnect with `This WinRS shell instance does not
  support disconnect and reconnect operations because it was created by an
  older WinRS client`, so the shells created through `WinrmPsrpTransport` are
  not marked disconnect-capable on any Windows tested. The whole
  disconnect/reconnect path remains covered by `MockTransport` only.

## [2.0.0] — 2026-09-03

Also ships everything listed under [1.1.0](#110--2026-06-03), which was
**never released** — it was only ever a version number in `Cargo.toml`,
with no tag and nothing published. 1.0.0 was the last release, so
upgrading from it picks up the SSH transport and host-key verification
as well as everything below.

### Breaking changes

- **`SshConfig` is now `#[non_exhaustive]`, and gains a builder**
  (`ssh` feature). The 1.1.0 work added a `host_key_policy` field to a
  struct that could be built with an exhaustive literal, which
  `cargo semver-checks` correctly flags as a major-version break. Rather
  than repeat that on the next field, the struct is now non-exhaustive —
  which means a struct expression from another crate is rejected
  outright, *including* `..SshConfig::default()`. Construct one with
  `SshConfig::new(host, username, auth)` plus `with_port`,
  `with_subsystem`, `with_connect_timeout` and `with_host_key_policy`:

  ```rust
  // before
  SshConfig { host: "h".into(), port: 2222, username: "u".into(),
              auth: SshAuth::Agent, ..Default::default() }
  // after
  SshConfig::new("h", "u", SshAuth::Agent).with_port(2222)
  ```

  The fields stay public, so an existing value can still be read and
  mutated in place.
- **MSRV raised to 1.98** (from 1.94).
- **`winrm-rs` requirement raised to `"1.2"`** (from `"1.0"`), so the
  fixed SOAP envelope builder cannot be resolved away. See below.

### Security

- **Remote denial of service in the CLIXML parser.** `parse_clixml` is
  recursive and the document comes from the remote host; with no depth
  limit, roughly 10 KiB of nested `<Obj><MS>` overflowed the stack and
  **aborted the process** (a stack overflow is not a catchable panic, so
  `#![forbid(unsafe_code)]` offered no protection). Nesting is now capped
  by the new public constant `MAX_NESTING_DEPTH` (64) and an over-deep
  document returns a structured error. Found by fuzzing.
- **Denial of service in SSH host-key verification.** The `known_hosts`
  glob matcher was recursive and explored every way of distributing the
  hostname across `*` wildcards, so a pattern such as `*a*a*a*a*b`
  against a long hostname hung the trust decision itself. Replaced with
  an iterative single-backtrack matcher: `O(n*m)`, no recursion, same
  semantics. Found by the `known_hosts_match` fuzz target.
- OpenSSH host **certificates** are now refused under every
  `HostKeyPolicy` except `AcceptAny`, since the crate carries no CA
  trust store. (russh 0.63 started surfacing them.)
- **A closed or broken runspace pool could be re-opened by the client.**
  `RunspacePoolStateMachine::open` / `connect` overwrote the state
  unconditionally, so a terminal machine could be driven back through
  the handshake into `Opened` — the very resurrection
  `is_legal_server_transition` already refused on the server side. Both
  now refuse once the machine is terminal, exposed as `is_terminal()`.
  Found by the `runspace_state_machine` fuzz target.

### Fixed

- **CLIXML attribute values were never XML-unescaped.** A property name
  containing `&`, `<`, `>`, `"` or `'` came back still escaped, and the
  encoder escaped it again on the next hop, so `&lt;` grew into
  `&amp;lt;` and onwards without bound. Attribute values are now
  normalised and `_xHHHH_`-decoded, mirroring the encoder exactly.
- **Tabs, CRs and LFs inside a property name were folded to spaces** by
  XML attribute-value normalisation. The encoder now emits them as
  `_xHHHH_` in attribute position (element text is unaffected).
- **A list or dictionary stored under the synthetic `_value` property
  did not round-trip.** The encoder wrote `<Obj><Obj><LST/></Obj></Obj>`;
  the decoder skips the inner `<Obj>` as an unknown element, silently
  dropping the container. The bare `<LST>` / `<DCT>` is now emitted.

### Added

- **Sixteen fuzz targets** (up from three), in five layers: raw wire
  decoders, structure-aware round-trips, the typed record/metadata/host
  decoders, the runspace state machine and the real async pool over a
  mock transport, and the small hand-rolled codecs. Beyond panic-freedom
  they assert protocol properties — reassembly is independent of byte
  chunking, the .NET mixed-endian GUIDs survive the header, the CLIXML
  codec reaches a fixed point, a closed or broken pool never returns to
  `Opened`, and the wrong session key never yields the right plaintext.
- Fuzzing infrastructure: `Arbitrary` value generators and round-trip
  semantics in `fuzz/src/lib.rs`, libFuzzer dictionaries for CLIXML /
  PSRP / `known_hosts`, a version-controlled seed corpus under
  `fuzz/seeds/`, a rewritten `fuzz/run.sh` (target auto-discovery,
  dictionaries, corpus seeding, `smoke` / `cmin` / `list` modes) and a
  new `fuzz/coverage.sh`.
- `MAX_NESTING_DEPTH` is re-exported at the crate root.
- GitHub Actions: a `CI` workflow (test matrix over the feature flags,
  fmt/clippy/docs, an **MSRV job that builds with exactly the declared
  `rust-version`**, and `cargo-deny`) and a `Fuzz` workflow (target build
  + seed-freshness check, a 60s smoke pass per target on pull requests,
  and a nightly 15-minute deep run with a persistent corpus cache).
- `deny.toml`, documenting why RUSTSEC-2023-0071 (`rsa`, no fixed
  release upstream) is accepted and what the exposure actually is.

### Changed

- **MSRV raised to 1.98** (`rust-version = "1.98"`), plus a
  `rust-toolchain.toml` pinning the `stable` channel with `clippy` and
  `rustfmt` for day-to-day work.
- **`quick-xml` 0.41 → 0.42.** The 0.42 event API is `str`-based instead
  of `[u8]`-based: `QName::as_ref`, `Attribute::key`/`value`,
  `BytesText`, `BytesCData` and `BytesRef` all yield `str` now.
  `clixml/decode.rs` was ported accordingly — behaviour is unchanged.
- **`russh` 0.62 → 0.63** (`ssh` feature). `Handler::check_server_key`
  now receives a `PublicKeyOrCertificate`. OpenSSH host *certificates*
  are refused (fail-closed) under every policy except
  `HostKeyPolicy::AcceptAny`, because the crate has no CA trust store.
- **`winrm-rs` 1.1.2 → 1.2.0, and the requirement raised from `"1.0"` to
  `"1.2"`.** 1.2.0 fixes an XML injection in the SOAP `ResourceURI`
  header and raises its own MSRV to 1.98 to match ours. `psrp-rs` passes
  a constant resource URI, so its own API does not reach the injection,
  but every request it makes goes through that envelope builder — and
  leaving the requirement at `"1.0"` would let a consumer resolve the
  unfixed version. Also pulls in `base64` 0.23.
- Routine bumps: `tokio` 1.53, `tokio-util` 0.7.19, `uuid` 1.26,
  `thiserror` 2.0.20, `indexmap` 2.14.1, `serde` 1.0.229, `aes` 0.9.3,
  `async-trait` 0.1.92.
- `hmac`, `rand` and `sha1` deliberately stay on the pre-`digest 0.11`
  generation (0.12 / 0.8 / 0.10): `rsa` 0.9 — the only stable release —
  pins `digest 0.10` and `rand_core 0.6`. Moving them would require
  `rsa 0.10.0-rc`, a pre-release that carries the *same* open advisory
  (RUSTSEC-2023-0071) and therefore buys no security.

## [1.1.0] — 2026-06-03

> **Never released.** This version number was set in `Cargo.toml` but
> never tagged and never published to crates.io; its contents ship as
> part of 2.0.0. Kept as its own section so the history stays readable.

### Added

- **SSH transport host-key verification**: new `HostKeyPolicy` enum on
  `SshConfig` with three modes — `KnownHosts` (default, consults
  `~/.ssh/known_hosts`), `Pinned` (accept only a key matching a given
  SHA-256 fingerprint), and `AcceptAny` (disables verification,
  opt-in only). Includes a `known_hosts` parser with glob host-pattern
  matching, hashed-host support, and constant-time key comparison.
- **Runspace pool state-machine validation**: `is_legal_server_transition`
  rejects illegal server-driven `RunspacePoolState` transitions
  (skipping negotiation, resurrecting a closed pool, etc.).

### Changed

- **CreatePipeline CLIXML construction** moved out of `pipeline.rs` into
  `clixml/encode.rs`, consolidating CLIXML fragment building in one place.

### Security

- Key material in `crypto` and `shared` is now wrapped with
  `ZeroizeOnDrop` and explicitly `zeroize()`d after use, so session and
  exchange keys are scrubbed from memory on drop.

### Dependencies

- Added `zeroize` (with `zeroize_derive`); added `hmac` under the `ssh`
  feature for hashed `known_hosts` entry matching.

## [1.0.0] — 2026-04-12

### Added

- **CLIXML primitives**: `<DT>`, `<TS>`, `<G>`, `<BA>`, `<C>`, `<By>`,
  `<SB>`, `<I16>`, `<U16>`, `<U32>`, `<U64>`, `<Sg>`, `<D>`, `<URI>`,
  `<Version>`, `<XD>`, `<SCT>`, `<SS>`. `PsValue` now carries each as a
  distinct variant so round-tripping through PowerShell preserves the
  tag.
- **`RefIdAllocator`**: monotonic ref-id numbering for CLIXML
  encoders. `escape` is now public so callers building CLIXML fragments
  outside the library can reuse the same escaping rules.
- **`PsObject::with_type_names`** and `PsObject.to_string` for full
  object fidelity.
- **Command positional arguments + switches**: `Command::with_argument`
  and `Command::with_switch`. The `Argument` enum is now public.
- **Error-stream merging**: `Command::merging_errors_to_output()` sets
  `MergeMyResult=Error` / `MergeToResult=Output` in the `CreatePipeline`
  body.
- **Pipeline input streaming**: `Pipeline::start` returns a
  `PipelineHandle` that exposes `write_input` / `end_input` / `stop` /
  `collect`. `Pipeline::with_input(true)` flips the `NoInput` flag off.
- **Stop / cancel**: every `run_*` method on `RunspacePool` and
  `Pipeline` has a `*_with_cancel` variant taking a
  `tokio_util::sync::CancellationToken`. Cancellation triggers
  `signal_ctrl_c` and returns `PsrpError::Cancelled` once the server
  ACKs `Stopped`.
- **Typed record accessors**: `records` module with `ErrorRecord`,
  `WarningRecord`, `InformationRecord`, `ProgressRecord`, `TraceRecord`,
  `ExceptionInfo`, `ErrorCategoryInfo`, `InvocationInfo`, plus
  `FromPsObject` trait. `PipelineResult::typed_errors()`,
  `typed_warnings()`, `typed_information()`, `typed_progress()`,
  `typed_verbose()`, `typed_debug()`.
- **Host call dispatch**: `host` module with `PsHost` trait,
  `NoInteractionHost` (default, safe for non-interactive), and
  `BufferedHost` (captures writes). `RunspacePool::open_with_options_and_host`
  plugs a custom host into the runspace. The receive loop intercepts
  `RunspacePoolHostCall` / `PipelineHostCall` messages and replies with
  the matching `*HostResponse`. `HostMethodId` enumerates the MS-PSRP
  §2.2.6 method ids.
- **Session-key cryptography**: `crypto` module with `ClientSessionKey`
  (pure-Rust RSA 2048 keygen + Windows `PUBLICKEYBLOB` format) and
  `SessionKey` (AES-256-CBC with PKCS#7 padding, UTF-16LE plaintext).
  `RunspacePool::request_session_key` drives the
  `PublicKey` → `EncryptedSessionKey` exchange.
  `RunspacePool::{encrypt,decrypt}_secure_string` give callers direct
  access to the negotiated key.
- **Concurrent pipelines**: `SharedRunspacePool<T>` wraps a pool in an
  `Arc<tokio::sync::Mutex<_>>` so multiple clones can submit scripts
  against the same long-lived pool. True wire-level concurrency is
  still serialised at the transport layer; concurrent API ergonomics
  are supported.
- **`get_command_metadata`**: a new pipeline kind used by implicit
  remoting. `CommandType` bitflags, `CommandMetadata` and
  `ParameterMetadata` structs expose the server's response.
- **`disconnect` / `DisconnectedPool::reconnect`** placeholders —
  return `PsrpError::Protocol` until `winrm-rs` exposes
  `Shell::disconnect` / `Shell::reconnect` upstream.
- **Fuzz targets** (`fuzz/fuzz_targets/`): `fragment_reassembler`,
  `clixml_decoder`, `message_decode`. Each ships a seed corpus
  generated by `examples/generate_fuzz_corpus.rs` and a wrapper
  `fuzz/run.sh` runner that drives them via the nightly toolchain.
- **`serde` feature** (optional): enable `Serialize` / `Deserialize`
  derives on `PsValue` / `PsObject` for JSON interop.
- **Integration test VM**: `Vagrantfile` for a Windows Server 2025
  Standard Eval Hyper-V box pre-provisioned with WinRM + PSRP enabled.
- **Live tests**: `tests/integration_real.rs` runs 7 scenarios
  (`1+1`, `Get-Date`, `Get-Process`, pipeline builder, Error stream,
  Warning stream, multi-pipeline) against the Vagrant box. All gated
  by `PSRP_INTEGRATION_HOST` env var.

### Changed

- `PsValue::as_str` now returns a match for every string-like variant
  (`String`, `Version`, `Uri`, `Xml`, `ScriptBlock`, `Decimal`,
  `DateTime`, `Duration`, `SecureString`).
- `PsValue::as_i32` narrows from any signed or unsigned integer variant
  that fits; `PsValue::as_i64` widens the same set.
- `runspace/` is now a module directory with a pure sync state machine
  in `state.rs` and the async driver in `pool.rs`.

### Fixed

- `PsrpMessage::decode` now succeeds on exactly-40-byte inputs (empty
  body). The off-by-one check previously rejected the boundary case.
- `escape` no longer escapes U+0020 (space) — only characters strictly
  below `0x20` are emitted as `_xHHHH_`.

## [0.1.0] — Initial skeleton

- Fragment layer, message header, basic CLIXML primitives, runspace
  pool, pipeline builder, transport trait, live Vagrant integration.
