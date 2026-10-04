use crypter_ir::IntegrityCheck;

pub fn emit_integrity(name: &str, check: &IntegrityCheck, payload_const: &str) -> String {
    let mut s = format!("fn {}() -> bool {{\n", name);
    match check {
        IntegrityCheck::TextSectionHash => {
            s.push_str(&format!("    let p = {};\n", payload_const));
            s.push_str("    let mut h = 0u64;\n");
            s.push_str("    for (i, &b) in p.iter().enumerate() {\n");
            s.push_str("        h = h.wrapping_mul(1099511628211).wrapping_add((b as u64) ^ (i as u64));\n");
            s.push_str("    }\n");
            s.push_str("    h != 0\n");
        }
        IntegrityCheck::RegionCrc { start, len } => {
            s.push_str(&format!("    let p = {};\n", payload_const));
            s.push_str(&format!("    let s = ({} as usize).min(p.len());\n", start));
            s.push_str(&format!("    let e = (s + {}).min(p.len());\n", len));
            s.push_str("    let mut c = 0xffffffffu32;\n");
            s.push_str("    for &b in &p[s..e] {\n");
            s.push_str("        c ^= b as u32;\n");
            s.push_str("        for _ in 0..8 { c = if c & 1 != 0 { (c >> 1) ^ 0xedb88320 } else { c >> 1 }; }\n");
            s.push_str("    }\n");
            s.push_str("    (!c) != 0\n");
        }
        IntegrityCheck::None => {
            s.push_str("    true\n");
        }
    }
    s.push_str("}\n\n");
    s
}
