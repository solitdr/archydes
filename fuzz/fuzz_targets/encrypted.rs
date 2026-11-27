#![no_main]
//! Encrypted archives (SPEC A11): KEY_INFO parsing, and whole archives opened with a fixed data
//! key (no Argon2, which would make every run slow) then verified and read.
use archydes_format::{KeyInfo, Keys};
use libfuzzer_sys::fuzz_target;

/// The data key of `seeds/encrypted.archy`.
const FUZZ_DEK: [u8; 32] = [0x42; 32];

fuzz_target!(|data: &[u8]| {
    let _ = KeyInfo::decode(data);
    let Ok(reader) = archydes_decode::Reader::open_with_keys(data.to_vec(), Keys::from_dek(FUZZ_DEK)) else { return };
    let _ = archydes_decode::verify(&reader, &mut |_, _| true);
    for snap in &reader.archive.index.snapshots {
        for e in &snap.entries {
            if e.kind == archydes_format::EntryKind::File && e.size <= 64 << 20 {
                let _ = reader.write_file(e, &mut Vec::new());
            }
        }
    }
});
