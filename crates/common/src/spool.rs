use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[derive(Serialize, Deserialize, Clone)]
pub struct SpoolEntry {
    pub tag: String,
    pub sealed: String,
    pub created: u64,
    pub attempts: u32,
}

pub struct Spool {
    dir: PathBuf,
    cap: usize,
    inner: Mutex<()>,
}

impl Spool {
    pub fn open() -> Self {
        let dir = spool_dir();
        let _ = std::fs::create_dir_all(&dir);
        Spool {
            dir,
            cap: 512,
            inner: Mutex::new(()),
        }
    }

    pub fn push(&self, tag: &str, sealed: &str) {
        let _g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        self.trim_if_needed();
        let created = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let entry = SpoolEntry {
            tag: tag.to_string(),
            sealed: sealed.to_string(),
            created,
            attempts: 0,
        };
        let name = format!("{}_{}.json", created, fast_id());
        let path = self.dir.join(&name);
        if let Ok(raw) = serde_json::to_vec(&entry) {
            let _ = std::fs::write(&path, raw);
        }
    }

    pub fn drain<F: FnMut(&str, &str) -> bool>(&self, mut send: F) {
        let _g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let mut files: Vec<PathBuf> = std::fs::read_dir(&self.dir)
            .ok()
            .map(|rd| {
                rd.flatten()
                    .map(|e| e.path())
                    .filter(|p| p.extension().and_then(|s| s.to_str()) == Some("json"))
                    .collect()
            })
            .unwrap_or_default();
        files.sort();
        for path in files {
            let raw = match std::fs::read(&path) {
                Ok(b) => b,
                Err(_) => continue,
            };
            let mut entry: SpoolEntry = match serde_json::from_slice(&raw) {
                Ok(e) => e,
                Err(_) => {
                    let _ = std::fs::remove_file(&path);
                    continue;
                }
            };
            if send(&entry.tag, &entry.sealed) {
                let _ = std::fs::remove_file(&path);
            } else {
                entry.attempts = entry.attempts.saturating_add(1);
                if entry.attempts >= 8 {
                    let _ = std::fs::remove_file(&path);
                    continue;
                }
                if let Ok(raw) = serde_json::to_vec(&entry) {
                    let _ = std::fs::write(&path, raw);
                }
            }
            std::thread::sleep(Duration::from_millis(150));
        }
    }

    fn trim_if_needed(&self) {
        let mut files: Vec<PathBuf> = std::fs::read_dir(&self.dir)
            .ok()
            .map(|rd| {
                rd.flatten()
                    .map(|e| e.path())
                    .filter(|p| p.extension().and_then(|s| s.to_str()) == Some("json"))
                    .collect()
            })
            .unwrap_or_default();
        if files.len() < self.cap {
            return;
        }
        files.sort();
        let drop_n = files.len().saturating_sub(self.cap);
        for p in files.into_iter().take(drop_n) {
            let _ = std::fs::remove_file(p);
        }
    }
}

pub fn spool_dir() -> PathBuf {
    #[cfg(windows)]
    {
        if let Ok(tmp) = std::env::var("TEMP") {
            return PathBuf::from(tmp).join("svc_spool");
        }
        PathBuf::from("C:\\Windows\\Temp\\svc_spool")
    }
    #[cfg(target_os = "linux")]
    {
        if let Ok(xdg) = std::env::var("XDG_CACHE_HOME") {
            return PathBuf::from(xdg).join("svc_spool");
        }
        if let Ok(home) = std::env::var("HOME") {
            return PathBuf::from(home).join(".cache/svc_spool");
        }
        PathBuf::from("/tmp/svc_spool")
    }
    #[cfg(target_os = "macos")]
    {
        if let Ok(home) = std::env::var("HOME") {
            return PathBuf::from(home).join("Library/Caches/svc_spool");
        }
        PathBuf::from("/tmp/svc_spool")
    }
}

fn fast_id() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or_else(|_| {
            use std::sync::atomic::{AtomicU64, Ordering};
            static C: AtomicU64 = AtomicU64::new(0);
            C.fetch_add(1, Ordering::Relaxed)
        })
}

pub fn rate_limit(min_interval: Duration) -> bool {
    use std::sync::OnceLock;
    static LAST: OnceLock<Mutex<Instant>> = OnceLock::new();
    let m = LAST.get_or_init(|| Mutex::new(Instant::now() - min_interval));
    let mut g = m.lock().unwrap_or_else(|e| e.into_inner());
    if g.elapsed() < min_interval {
        return false;
    }
    *g = Instant::now();
    true
}
