use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SysInfo {
    pub hostname: String,
    pub username: String,
    pub os: String,
    pub arch: String,
    pub cwd: String,
    pub pid: u32,
}

impl SysInfo {
    pub fn collect() -> Self {
        Self {
            hostname: hostname::get().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default(),
            username: whoami::username(),
            os: std::env::consts::OS.to_string(),
            arch: std::env::consts::ARCH.to_string(),
            cwd: std::env::current_dir().map(|p| p.display().to_string()).unwrap_or_default(),
            pid: std::process::id(),
        }
    }
}
