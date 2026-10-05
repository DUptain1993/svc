//! Fixed-name helper functions used by gates, debug checks, and
//! anti-emulation code. Each helper is emitted at most once per stub,
//! tracked by `Synth::ensure_helper`. Names are fixed (not per-build
//! randomized) so gates can reference them without coordination.
//!
//! Helpers are cfg-gated internally: Windows x86_64 gets the real
//! PEB/asm path; everything else compiles a null-returning fallback
//! so the source is portable and clippy-clean.

pub fn source_for(name: &str) -> Option<&'static str> {
    match name {
        "peb_ptr" => Some(PEB_PTR),
        "lower_u16" => Some(LOWER_U16),
        "load_ntdll" => Some(LOAD_NTDLL),
        "load_kernel32" => Some(LOAD_KERNEL32),
        "resolve_export" => Some(RESOLVE_EXPORT),
        "nt_sleep_ms" => Some(NT_SLEEP_MS),
        _ => None,
    }
}

/// Transitive deps — `ensure_helper` walks this recursively.
pub fn deps_for(name: &str) -> &'static [&'static str] {
    match name {
        "load_ntdll" => &["peb_ptr", "lower_u16"],
        "load_kernel32" => &["peb_ptr", "lower_u16"],
        "resolve_export" => &[],
        "nt_sleep_ms" => &["peb_ptr", "load_ntdll", "resolve_export"],
        "peb_ptr" => &[],
        "lower_u16" => &[],
        _ => &[],
    }
}

const PEB_PTR: &str = r#"
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
unsafe fn peb_ptr() -> *const u8 {
    let peb: *const u8;
    core::arch::asm!("mov {}, gs:[0x60]", out(reg) peb);
    peb
}

#[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
unsafe fn peb_ptr() -> *const u8 {
    ptr::null()
}
"#;

const LOWER_U16: &str = r#"
fn lower_u16(c: u16) -> u16 {
    if c >= 0x41 && c <= 0x5A { c + 0x20 } else { c }
}
"#;

const LOAD_NTDLL: &str = r#"
unsafe fn load_ntdll() -> *mut c_void {
    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    {
        let peb = peb_ptr();
        if peb.is_null() { return ptr::null_mut(); }
        let ldr = *((peb as *const u8).add(0x18) as *const *const u8);
        if ldr.is_null() { return ptr::null_mut(); }
        let head = (ldr as *const u8).add(0x10) as *const u8;
        let mut entry = *((ldr as *const u8).add(0x10) as *const *const u8);
        for _ in 0..64 {
            if entry == head { break; }
            let dll_base = *((entry as *const u8).add(0x30) as *const *mut c_void);
            let name_len = *((entry as *const u8).add(0x48) as *const u16);
            let name_buf = *((entry as *const u8).add(0x50) as *const *const u16);
            if name_len >= 12 && !name_buf.is_null() {
                let matches = (0..12u16).all(|i| {
                    lower_u16(*name_buf.add(i as usize)) == lower_u16("ntdll.dll".encode_utf16().nth(i as usize).unwrap_or(0))
                });
                if matches { return dll_base; }
            }
            entry = *((entry as *const u8).add(0x00) as *const *const u8);
        }
    }
    ptr::null_mut()
}
"#;

const LOAD_KERNEL32: &str = r#"
unsafe fn load_kernel32() -> *mut c_void {
    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    {
        let peb = peb_ptr();
        if peb.is_null() { return ptr::null_mut(); }
        let ldr = *((peb as *const u8).add(0x18) as *const *const u8);
        if ldr.is_null() { return ptr::null_mut(); }
        let head = (ldr as *const u8).add(0x10) as *const u8;
        let mut entry = *((ldr as *const u8).add(0x10) as *const *const u8);
        for _ in 0..64 {
            if entry == head { break; }
            let dll_base = *((entry as *const u8).add(0x30) as *const *mut c_void);
            let name_len = *((entry as *const u8).add(0x48) as *const u16);
            let name_buf = *((entry as *const u8).add(0x50) as *const *const u16);
            if name_len >= 12 && !name_buf.is_null() {
                let k32: [u16; 12] = ['k' as u16,'e' as u16,'r' as u16,'n' as u16,'e' as u16,'l' as u16,'3' as u16,'2' as u16,'.' as u16,'d' as u16,'l' as u16,'l' as u16];
                let kb: [u16; 13] = ['k' as u16,'e' as u16,'r' as u16,'n' as u16,'e' as u16,'l' as u16,'b' as u16,'a' as u16,'s' as u16,'e' as u16,'.' as u16,'d' as u16,'l' as u16];
                let mut is_k32 = name_len >= 12;
                for i in 0..12 {
                    if lower_u16(*name_buf.add(i)) != k32[i] { is_k32 = false; break; }
                }
                if is_k32 { return dll_base; }
                let mut is_kb = name_len >= 13;
                for i in 0..13 {
                    if lower_u16(*name_buf.add(i)) != kb[i] { is_kb = false; break; }
                }
                if is_kb { return dll_base; }
            }
            entry = *((entry as *const u8).add(0x00) as *const *const u8);
        }
    }
    ptr::null_mut()
}
"#;

const RESOLVE_EXPORT: &str = r#"
unsafe fn resolve_export(module: *mut c_void, name: &[u8]) -> *const u8 {
    #[cfg(target_os = "windows")]
    {
        if module.is_null() { return ptr::null(); }
        let base = module as *const u8;
        let e_lfanew = *((base).add(0x3c) as *const u32) as usize;
        let nt = base.add(e_lfanew);
        let exp_rva = *(nt.add(0x88) as *const u32) as usize;
        if exp_rva == 0 { return ptr::null(); }
        let exp = base.add(exp_rva);
        let num_names = *(exp.add(0x18) as *const u32) as usize;
        let addr_names = base.add(*(exp.add(0x20) as *const u32) as usize) as *const u32;
        let addr_ords  = base.add(*(exp.add(0x24) as *const u32) as usize) as *const u16;
        let addr_funcs = base.add(*(exp.add(0x1c) as *const u32) as usize) as *const u32;
        let target = &name[..name.len().saturating_sub(1)];
        for i in 0..num_names {
            let n = base.add(*addr_names.add(i) as usize);
            let mut len = 0usize;
            while *n.add(len) != 0 { len += 1; }
            let slice = std::slice::from_raw_parts(n, len);
            if slice == target {
                let ord = *addr_ords.add(i) as usize;
                let fn_rva = *addr_funcs.add(ord) as usize;
                return base.add(fn_rva);
            }
        }
    }
    #[cfg(not(target_os = "windows"))]
    { let _ = (module, name); }
    ptr::null()
}
"#;

const NT_SLEEP_MS: &str = r#"
fn nt_sleep_ms(ms: u64) {
    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    unsafe {
        let ntdll = load_ntdll();
        if !ntdll.is_null() {
            let p = resolve_export(ntdll, b"NtDelayExecution\0");
            if !p.is_null() {
                let f: unsafe extern "system" fn(u8, *mut i64) -> i32 = mem::transmute(p);
                let mut interval: i64 = -((ms as i64) * 10_000);
                let _ = f(0, &mut interval);
                return;
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(ms));
    }
    #[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
    {
        std::thread::sleep(std::time::Duration::from_millis(ms));
    }
}
"#;
