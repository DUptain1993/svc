use std::ffi::CString;
use std::os::unix::io::RawFd;

extern "C" {
    fn memfd_create(name: *const i8, flags: u32) -> i32;
    fn fexecve(fd: i32, argv: *const *const i8, envp: *const *const i8) -> i32;
    fn fork() -> i32;
    fn write(fd: i32, buf: *const u8, count: usize) -> isize;
    fn exit(code: i32) -> !;
}

const MFD_CLOEXEC: u32 = 0x0001;

pub fn spawn_memfd(payload: &[u8], argv: &[&str]) -> Result<(), &'static str> {
    unsafe {
        let name = CString::new("svc").unwrap();
        let fd = memfd_create(name.as_ptr(), MFD_CLOEXEC);
        if fd < 0 {
            return Err("memfd_create");
        }
        let mut written = 0usize;
        while written < payload.len() {
            let n = write(fd, payload.as_ptr().add(written), payload.len() - written);
            if n <= 0 {
                return Err("write");
            }
            written += n as usize;
        }
        let pid = fork();
        if pid < 0 {
            return Err("fork");
        }
        if pid == 0 {
            let cstrs: Vec<CString> = argv.iter().map(|s| CString::new(*s).unwrap()).collect();
            let mut ptrs: Vec<*const i8> = cstrs.iter().map(|c| c.as_ptr()).collect();
            ptrs.push(std::ptr::null());
            fexecve(fd as RawFd, ptrs.as_ptr(), std::ptr::null());
            exit(127);
        }
        Ok(())
    }
}
