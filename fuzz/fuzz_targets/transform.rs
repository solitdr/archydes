//! Hostile part inputs for ZLIB_EXACT, PREFLATE and JPEG_FROM_JXL (SPEC A7): an error is fine,
//! a crash, a hang or unbounded memory is not.
#![no_main]

use archydes_decode::transform::{jxl_part_params, preflate_part_params, rebuild_part, zlib_part_params};
use archydes_format::Part;
use archydes_format::consts::transform;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Panics inside preflate-rs and jxl-oxide are caught and reported as damage; keep the hook
    // quiet so only panics outside those guards count as crashes (libfuzzer-sys catches them).
    static QUIET: std::sync::Once = std::sync::Once::new();
    QUIET.call_once(|| std::panic::set_hook(Box::new(|_| {})));

    let [kind, a, b, c, rest @ ..] = data else { return };
    // PREFLATE: a, b, c are the length of the first input (24 bits).
    let split = ((*a as usize) << 16 | (*b as usize) << 8 | *c as usize).min(rest.len());
    let (first, second) = rest.split_at(split);
    let part = match kind % 3 {
        0 => {
            let p = archydes_zlib::Params {
                wbits: -15 + (*a as i32 % 40),
                level: *b as i32 % 12 - 1,
                memlevel: *c as i32 % 10 + 1,
                strategy: (*a >> 6) as i32,
            };
            Part { transform: transform::ZLIB_EXACT, params: zlib_part_params(p), inputs: vec![vec![]] }
        }
        1 => Part { transform: transform::PREFLATE, params: preflate_part_params(), inputs: vec![vec![], vec![]] },
        _ => Part { transform: transform::JPEG_FROM_JXL, params: jxl_part_params("fuzz"), inputs: vec![vec![]] },
    };
    let inputs: [&[u8]; 2] = if kind % 3 == 1 { [first, second] } else { [rest, &[]] };
    let mut out = 0usize;
    let _ = rebuild_part(&part, &mut |k, s| s(inputs[k]), &mut |chunk| {
        out += chunk.len();
        if out > 64 << 20 { Err(archydes_format::corrupt("too much output")) } else { Ok(()) }
    });
});
