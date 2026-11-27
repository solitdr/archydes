//! Test vectors that fix the meaning of the transforms in SPEC A7. They must keep decoding
//! bit-exactly forever: a failing vector means a format break, not a test to update.

use archydes_decode::transform::{jxl_part_params, part_reproduces, preflate_part_params};
use archydes_format::Part;
use archydes_format::consts::transform;

/// The text the PREFLATE vector was made from.
fn text() -> Vec<u8> {
    (0..5000).flat_map(|i| format!("<row r=\"{i}\"><c>{}</c></row>", i * 7 % 13).into_bytes()).collect()
}

#[test]
fn jpeg_from_jxl_vector() {
    let jpeg = include_bytes!("vectors/gradient.jpg");
    let jxl = include_bytes!("vectors/gradient.jxl");
    let part =
        Part { transform: transform::JPEG_FROM_JXL, params: jxl_part_params("libjxl 0.13.0"), inputs: vec![vec![]] };
    assert!(part_reproduces(&part, &[jxl], jpeg));
}

/// `ver = "preflate-rs-0.7.6/archydes-rc-1"`: corrections of a Z_FILTERED stream.
#[test]
fn preflate_archydes_rc_1_vector() {
    let plain = text();
    let deflate =
        archydes_zlib::deflate(&plain, archydes_zlib::Params { wbits: -15, level: 6, memlevel: 8, strategy: 1 })
            .unwrap();
    // zlib 1.3.1 is fixed too (D-011): the input stream of the vector is always these bytes.
    let h: String = archydes_format::hash256(&deflate).iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(h, "b21a0db394e456a2bd5c7edadfc38441e5346d8daf2d7bcb528043b88dfa613e");
    let corrections = include_bytes!("vectors/preflate-filtered.corr");
    let part = Part { transform: transform::PREFLATE, params: preflate_part_params(), inputs: vec![vec![], vec![]] };
    assert!(part_reproduces(&part, &[&plain, corrections], &deflate));
}
