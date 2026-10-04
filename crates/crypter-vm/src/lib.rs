use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use sha2::{Digest, Sha256};

pub const OP_COUNT: usize = 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Op {
    PushConst = 0,
    Pop = 1,
    Dup = 2,
    Swap = 3,
    Add = 4,
    Sub = 5,
    Xor = 6,
    And = 7,
    Or = 8,
    Shl = 9,
    Shr = 10,
    Jmp = 11,
    Jz = 12,
    Jnz = 13,
    CallGate = 14,
    CheckDebug = 15,
    CheckAntiEmu = 16,
    UnwrapKey = 17,
    Decrypt = 18,
    CheckIntegrity = 19,
    Protect = 20,
    Unprotect = 21,
    Exec = 22,
    HaltOk = 23,
    HaltFail = 24,
    Nop = 25,
    Not = 26,
    Eq = 27,
    Lt = 28,
    Gt = 29,
    Reserved0 = 30,
    Reserved1 = 31,
}

#[derive(Clone)]
pub struct Encoding {
    pub forward: [u8; OP_COUNT],
    pub reverse: [u8; 256],
    pub host_vtable: [u8; 16],
}

impl Encoding {
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        let mut rng = StdRng::from_seed(*seed);
        let mut codes: Vec<u8> = (0..=255u8).collect();
        for i in (1..codes.len()).rev() {
            let j = rng.gen_range(0..=i);
            codes.swap(i, j);
        }
        let mut forward = [0u8; OP_COUNT];
        let mut reverse = [0u8; 256];
        for i in 0..OP_COUNT {
            forward[i] = codes[i];
            reverse[codes[i] as usize] = i as u8;
        }
        let mut h: Vec<u8> = (0..16u8).collect();
        for i in (1..h.len()).rev() {
            let j = rng.gen_range(0..=i);
            h.swap(i, j);
        }
        let mut host_vtable = [0u8; 16];
        host_vtable.copy_from_slice(&h);
        Encoding {
            forward,
            reverse,
            host_vtable,
        }
    }

    pub fn emit_rust(&self) -> String {
        let mut s = String::new();
        s.push_str("const ENC_FORWARD: [u8; 32] = [");
        for (i, b) in self.forward.iter().enumerate() {
            if i > 0 {
                s.push(',');
            }
            s.push_str(&format!("{:#04x}", b));
        }
        s.push_str("];\n");
        s.push_str("const ENC_REVERSE: [u8; 256] = [");
        for (i, b) in self.reverse.iter().enumerate() {
            if i > 0 {
                s.push(',');
            }
            if i % 16 == 0 {
                s.push('\n');
            }
            s.push_str(&format!("{:#04x}", b));
        }
        s.push_str("];\n");
        s.push_str("const ENC_HOST: [u8; 16] = [");
        for (i, b) in self.host_vtable.iter().enumerate() {
            if i > 0 {
                s.push(',');
            }
            s.push_str(&format!("{:#04x}", b));
        }
        s.push_str("];\n");
        s
    }
}

pub struct ProgramBuilder {
    pub encoding: Encoding,
    pub code: Vec<u8>,
}

impl ProgramBuilder {
    pub fn new(encoding: Encoding) -> Self {
        Self {
            encoding,
            code: Vec::new(),
        }
    }

    pub fn op(&mut self, op: Op) {
        self.code.push(self.encoding.forward[op as usize]);
    }

    pub fn u8(&mut self, v: u8) {
        self.code.push(v);
    }

    pub fn u16(&mut self, v: u16) {
        self.code.push((v >> 8) as u8);
        self.code.push((v & 0xff) as u8);
    }

    pub fn u32(&mut self, v: u32) {
        self.code.push((v >> 24) as u8);
        self.code.push((v >> 16) as u8);
        self.code.push((v >> 8) as u8);
        self.code.push((v & 0xff) as u8);
    }

    pub fn emit_bytes(&self) -> Vec<u8> {
        self.code.clone()
    }
}

pub fn seed_for_build(payload_hash: &[u8; 32], nonce: &[u8; 16]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"crypter_isa_v2");
    h.update(payload_hash);
    h.update(nonce);
    let mut out = [0u8; 32];
    out.copy_from_slice(&h.finalize());
    out
}
