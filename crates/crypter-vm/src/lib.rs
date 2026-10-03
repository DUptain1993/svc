use rand::{Rng, SeedableRng};
use rand::rngs::StdRng;
use sha2::{Digest, Sha256};

pub const OP_COUNT: usize = 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Op {
    PushU32 = 0, PushU64 = 1, Dup = 2, Drop = 3, Swap = 4,
    Add = 5, Sub = 6, Xor = 7, And = 8, Or = 9, Shl = 10, Shr = 11,
    Jmp = 12, Jz = 13, Jnz = 14, Call = 15, Ret = 16, Halt = 17,
    LoadU8 = 18, StoreU8 = 19, LoadU64 = 20, StoreU64 = 21,
    HostCall = 22, Not = 23, Eq = 24, Lt = 25, Gt = 26, Nop = 27,
    Reserved0 = 28, Reserved1 = 29, Reserved2 = 30, Reserved3 = 31,
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
        Encoding { forward, reverse, host_vtable }
    }

    pub fn emit_rust(&self) -> String {
        let mut s = String::new();
        s.push_str("const ENC_FORWARD: [u8; 32] = [");
        for (i, b) in self.forward.iter().enumerate() {
            if i > 0 { s.push(','); }
            s.push_str(&format!("{:#04x}", b));
        }
        s.push_str("];\n");
        s.push_str("const ENC_REVERSE: [u8; 256] = [");
        for (i, b) in self.reverse.iter().enumerate() {
            if i > 0 { s.push(','); }
            if i % 16 == 0 { s.push('\n'); }
            s.push_str(&format!("{:#04x}", b));
        }
        s.push_str("];\n");
        s.push_str("const ENC_HOST: [u8; 16] = [");
        for (i, b) in self.host_vtable.iter().enumerate() {
            if i > 0 { s.push(','); }
            s.push_str(&format!("{:#04x}", b));
        }
        s.push_str("];\n");
        s
    }
}

pub fn seed_for_build(payload_hash: &[u8; 32], nonce: &[u8; 16]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"crypter_isa_v1");
    h.update(payload_hash);
    h.update(nonce);
    let mut out = [0u8; 32];
    out.copy_from_slice(&h.finalize());
    out
}
