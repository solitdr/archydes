#![no_main]
//! Whole archives: open, verify, extract every file into memory.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(reader) = archydes_decode::Reader::open(data.to_vec()) else { return };
    let _ = archydes_decode::verify(&reader, &mut |_, _| true);
    for snap in &reader.archive.index.snapshots {
        for e in &snap.entries {
            if e.kind == archydes_format::EntryKind::File && e.size <= 64 << 20 {
                let mut out = Vec::new();
                let _ = reader.write_file(e, &mut out);
            }
            for (_, s) in &e.xattrs {
                let _ = reader.stream_bytes(s);
            }
        }
    }
});
