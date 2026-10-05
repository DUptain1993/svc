//! VM dispatch emitter. Per-build ISA tables come from `crypter-vm`.

use rand::rngs::StdRng;

pub fn emit_vm_dispatch(rng: &mut StdRng, seed: &[u8; 32]) -> String {
    let _ = (rng, seed);

    let mut s = String::new();

    s.push_str("fn vm_run(code: &[u8]) -> i64 {\n");
    s.push_str("    let mut stack: Vec<i64> = Vec::with_capacity(64);\n");
    s.push_str("    let mut pc = 0usize;\n");
    s.push_str("    while pc < code.len() {\n");
    s.push_str("        let op = ENC_REVERSE[code[pc] as usize];\n");
    s.push_str("        pc += 1;\n");
    s.push_str("        match op {\n");
    s.push_str("            0 => { let v = read_u32(code, &mut pc) as i64; stack.push(v); }\n");
    s.push_str("            1 => { let v = read_u64(code, &mut pc) as i64; stack.push(v); }\n");
    s.push_str("            2 => { let v = *stack.last().unwrap_or(&0); stack.push(v); }\n");
    s.push_str("            3 => { stack.pop(); }\n");
    s.push_str("            4 => { let a = stack.pop().unwrap_or(0); let b = stack.pop().unwrap_or(0); stack.push(a); stack.push(b); }\n");
    s.push_str("            5 => { let a = stack.pop().unwrap_or(0); let b = stack.pop().unwrap_or(0); stack.push(b.wrapping_add(a)); }\n");
    s.push_str("            6 => { let a = stack.pop().unwrap_or(0); let b = stack.pop().unwrap_or(0); stack.push(b.wrapping_sub(a)); }\n");
    s.push_str("            7 => { let a = stack.pop().unwrap_or(0); let b = stack.pop().unwrap_or(0); stack.push(b ^ a); }\n");
    s.push_str("            8 => { let a = stack.pop().unwrap_or(0); let b = stack.pop().unwrap_or(0); stack.push(b & a); }\n");
    s.push_str("            9 => { let a = stack.pop().unwrap_or(0); let b = stack.pop().unwrap_or(0); stack.push(b | a); }\n");
    s.push_str("            10 => { let a = stack.pop().unwrap_or(0); let b = stack.pop().unwrap_or(0); stack.push(b << (a & 63)); }\n");
    s.push_str("            11 => { let a = stack.pop().unwrap_or(0); let b = stack.pop().unwrap_or(0); stack.push(b >> (a & 63)); }\n");
    s.push_str("            12 => { let off = read_u32(code, &mut pc) as usize; pc += off; }\n");
    s.push_str("            13 => { let off = read_u32(code, &mut pc) as usize; if stack.pop().unwrap_or(0) == 0 { pc += off; } }\n");
    s.push_str("            14 => { let off = read_u32(code, &mut pc) as usize; if stack.pop().unwrap_or(0) != 0 { pc += off; } }\n");
    s.push_str("            15 => { let target = read_u32(code, &mut pc) as usize; stack.push(pc as i64); pc = target; }\n");
    s.push_str("            16 => { if let Some(t) = stack.pop() { pc = t as usize; } else { return 0; } }\n");
    s.push_str("            17 => { return stack.pop().unwrap_or(0); }\n");
    s.push_str("            18 => { let a = stack.pop().unwrap_or(0) as usize; stack.push(code.get(a).copied().unwrap_or(0) as i64); }\n");
    s.push_str("            19 => { let v = stack.pop().unwrap_or(0) as u8; let a = stack.pop().unwrap_or(0) as usize; let _ = (a, v); }\n");
    s.push_str("            20 => { let a = stack.pop().unwrap_or(0) as usize; let v = read_u64(code, &mut pc) as i64; let _ = (a, v); }\n");
    s.push_str("            21 => { let v = stack.pop().unwrap_or(0); let a = stack.pop().unwrap_or(0) as usize; let _ = (a, v); }\n");
    s.push_str("            22 => { let idx = code.get(pc).copied().unwrap_or(0) as usize; pc += 1; let logical = ENC_HOST[idx & 15]; let r = host_dispatch(logical, &mut stack); stack.push(r); }\n");
    s.push_str("            23 => { let a = stack.pop().unwrap_or(0); stack.push(!a); }\n");
    s.push_str("            24 => { let a = stack.pop().unwrap_or(0); let b = stack.pop().unwrap_or(0); stack.push((b == a) as i64); }\n");
    s.push_str("            25 => { let a = stack.pop().unwrap_or(0); let b = stack.pop().unwrap_or(0); stack.push((b < a) as i64); }\n");
    s.push_str("            26 => { let a = stack.pop().unwrap_or(0); let b = stack.pop().unwrap_or(0); stack.push((b > a) as i64); }\n");
    s.push_str("            27 => {}\n");
    s.push_str("            _ => {}\n");
    s.push_str("        }\n");
    s.push_str("    }\n");
    s.push_str("    0\n");
    s.push_str("}\n\n");

    s.push_str("fn read_u32(code: &[u8], pc: &mut usize) -> u32 {\n");
    s.push_str("    let mut v = 0u32;\n");
    s.push_str("    for _ in 0..4 {\n");
    s.push_str("        v = (v << 8) | code.get(*pc).copied().unwrap_or(0) as u32;\n");
    s.push_str("        *pc += 1;\n");
    s.push_str("    }\n");
    s.push_str("    v\n");
    s.push_str("}\n\n");

    s.push_str("fn read_u64(code: &[u8], pc: &mut usize) -> u64 {\n");
    s.push_str("    let mut v = 0u64;\n");
    s.push_str("    for _ in 0..8 {\n");
    s.push_str("        v = (v << 8) | code.get(*pc).copied().unwrap_or(0) as u64;\n");
    s.push_str("        *pc += 1;\n");
    s.push_str("    }\n");
    s.push_str("    v\n");
    s.push_str("}\n\n");

    s.push_str("fn host_dispatch(_id: u8, _stack: &mut Vec<i64>) -> i64 {\n");
    s.push_str("    0\n");
    s.push_str("}\n\n");

    s
}
