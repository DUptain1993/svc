use crypter_ir::TargetOs;

pub fn emit_antidump_fn(name: &str, target: TargetOs) -> String {
    let mut s = String::new();
    s.push_str("static ADP_ARMED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);\n");
    s.push_str("static ADP_PTR: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);\n");
    s.push_str("static ADP_LEN: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);\n\n");

    s.push_str(&format!("mod {} {{\n", name));
    s.push_str("    use super::*;\n");
    s.push_str("    use std::sync::atomic::Ordering;\n\n");

    match target {
        TargetOs::Windows => {
            s.push_str(r#"    pub struct Guard {
        ptr: *mut u8,
        len: usize,
        old: u32,
    }

    pub fn protect(data: &[u8]) -> Guard {
        let ptr = data.as_ptr() as *mut u8;
        let len = data.len();
        let mut old: u32 = 0;
        unsafe {
            let ok = VirtualProtect(ptr as *mut c_void, len, PAGE_NOACCESS, &mut old);
            if ok == 0 {
                return Guard { ptr, len, old: PAGE_READWRITE };
            }
        }
        super::ADP_PTR.store(ptr as usize, Ordering::SeqCst);
        super::ADP_LEN.store(len, Ordering::SeqCst);
        Guard { ptr, len, old }
    }

    pub fn unprotect(g: &Guard) {
        unsafe {
            let mut old: u32 = 0;
            let _ = VirtualProtect(g.ptr as *mut c_void, g.len, PAGE_EXECUTE_READ, &mut old);
        }
    }

    pub fn install_watchdog() {
        super::ADP_ARMED.store(true, Ordering::SeqCst);
        std::thread::spawn(|| {
            loop {
                if !super::ADP_ARMED.load(Ordering::SeqCst) {
                    std::thread::sleep(std::time::Duration::from_millis(50));
                    continue;
                }
                let ptr = super::ADP_PTR.load(Ordering::SeqCst);
                let len = super::ADP_LEN.load(Ordering::SeqCst);
                if ptr != 0 && len != 0 {
                    unsafe {
                        let mut old: u32 = 0;
                        let _ = VirtualProtect(ptr as *mut c_void, len, PAGE_NOACCESS, &mut old);
                    }
                }
                std::thread::sleep(std::time::Duration::from_micros(200));
            }
        });
    }

    pub fn disarm() {
        super::ADP_ARMED.store(false, Ordering::SeqCst);
    }
"#);
        }
        TargetOs::Linux | TargetOs::Macos => {
            s.push_str(r#"    pub struct Guard {
        ptr: *mut u8,
        len: usize,
    }

    pub fn protect(data: &[u8]) -> Guard {
        let ptr = data.as_ptr() as *mut u8;
        let len = data.len();
        let page = 4096usize;
        let start = (ptr as usize) & !(page - 1);
        let end = ((ptr as usize + len) + page - 1) & !(page - 1);
        let size = end - start;
        unsafe { let _ = mprotect(start as *mut c_void, size, PROT_NONE); }
        super::ADP_PTR.store(ptr as usize, Ordering::SeqCst);
        super::ADP_LEN.store(len, Ordering::SeqCst);
        Guard { ptr, len }
    }

    pub fn unprotect(g: &Guard) {
        let page = 4096usize;
        let start = (g.ptr as usize) & !(page - 1);
        let end = ((g.ptr as usize + g.len) + page - 1) & !(page - 1);
        let size = end - start;
        unsafe { let _ = mprotect(start as *mut c_void, size, PROT_READ | PROT_EXEC); }
    }

    pub fn install_watchdog() {
        super::ADP_ARMED.store(true, Ordering::SeqCst);
        std::thread::spawn(|| {
            let page = 4096usize;
            loop {
                if !super::ADP_ARMED.load(Ordering::SeqCst) {
                    std::thread::sleep(std::time::Duration::from_millis(50));
                    continue;
                }
                let ptr = super::ADP_PTR.load(Ordering::SeqCst);
                let len = super::ADP_LEN.load(Ordering::SeqCst);
                if ptr != 0 && len != 0 {
                    let start = ptr & !(page - 1);
                    let end = (ptr + len + page - 1) & !(page - 1);
                    let size = end - start;
                    unsafe { let _ = mprotect(start as *mut c_void, size, PROT_NONE); }
                }
                std::thread::sleep(std::time::Duration::from_micros(200));
            }
        });
    }

    pub fn disarm() {
        super::ADP_ARMED.store(false, Ordering::SeqCst);
    }

    extern "C" {
        fn mprotect(addr: *mut c_void, len: usize, prot: i32) -> i32;
    }
    const PROT_NONE: i32 = 0;
    const PROT_READ: i32 = 1;
    const PROT_EXEC: i32 = 4;
"#);
        }
    }

    s.push_str("}\n\n");

    if matches!(target, TargetOs::Windows) {
        s.push_str(r#"#[cfg(target_os = "windows")]
extern "system" {
    fn VirtualProtect(addr: *mut c_void, size: usize, new: u32, old: *mut u32) -> i32;
}
#[cfg(target_os = "windows")]
const PAGE_NOACCESS: u32 = 0x01;
#[cfg(target_os = "windows")]
const PAGE_READWRITE: u32 = 0x04;
#[cfg(target_os = "windows")]
const PAGE_EXECUTE_READ: u32 = 0x20;

"#);
    }

    s
}
