use rand::Rng;

pub fn emit_junk_block<R: Rng>(rng: &mut R, density: f32) -> String {
    if rng.gen::<f32>() > density {
        return String::new();
    }
    let n = rng.gen_range(2..6);
    let mut s = String::new();
    s.push_str("    if black_box(false) {\n");
    for _ in 0..n {
        let kind = rng.gen_range(0..4);
        match kind {
            0 => {
                let a: u64 = rng.gen();
                let b: u64 = rng.gen();
                s.push_str(&format!(
                    "        let _x = black_box({}u64).wrapping_mul(black_box({}u64));\n",
                    a, b
                ));
            }
            1 => {
                let v: u32 = rng.gen();
                s.push_str(&format!(
                    "        let _x = black_box({}u32) ^ black_box({}u32);\n",
                    v,
                    v.rotate_left(7)
                ));
            }
            2 => {
                s.push_str("        let _x: Vec<u8> = (0..16).map(|i| (i as u8).wrapping_mul(7)).collect();\n");
                s.push_str("        let _ = black_box(_x.len());\n");
            }
            _ => {
                s.push_str("        for _i in 0..black_box(4) { std::hint::spin_loop(); }\n");
            }
        }
    }
    s.push_str("    }\n");
    s
}
