//! Encrypted archives (SPEC A11) end to end: extract, verify, structure check without the
//! password, and the fixed test vector `vectors/encrypted-1.1.archy`.

use std::fs;

use archydes_decode::{ExtractOptions, Reader};
use archydes_format::consts::{FORMAT_MINOR_ENCRYPTED, codec, flags};
use archydes_format::index::{Chunk, ChunkTable, Index};
use archydes_format::{
    ArchiveWriter, Encryption, Entry, EntryKind, Error, Header, KdfParams, Keys, PackHeader, Part, Snapshot,
};

/// Password of the test vector, in NFC; the test opens it with the NFD spelling.
const PASSWORD: &str = "Pr\u{fc}fung 1.1";
const PASSWORD_NFD: &str = "Pru\u{308}fung 1.1";
const VECTOR_FILE: &str = "Hallo, Archydes!\nDas ist der Testvektor f\u{fc}r verschl\u{fc}sselte Archive.\n";

fn file(path: &str, data: &[u8], chunk: u32) -> Entry {
    Entry {
        path: path.as_bytes().to_vec(),
        path_nfc: path.into(),
        kind: EntryKind::File,
        mode: 0o644,
        mtime_ns: 1_764_115_200_000_000_000,
        btime_ns: None,
        xattrs: vec![],
        target: None,
        size: data.len() as u64,
        hash: Some(archydes_format::hash256(data)),
        recipe: Some(vec![Part::raw(vec![chunk])]),
    }
}

/// One file in one pack, zstd-compressed, encrypted with the minimum Argon2 parameters.
fn build(password: &str, data: &[u8]) -> Vec<u8> {
    build_keyed(Keys::create(password, b"archydes-vector1", KdfParams::MINIMUM).unwrap(), data)
}

fn build_keyed((keys, info): (Keys, archydes_format::KeyInfo), data: &[u8]) -> Vec<u8> {
    let uuid = *b"archydes-vector1";
    let mut header = Header::new(flags::ENCRYPTED, uuid, 1_764_115_200_000_000_000);
    header.minor = FORMAT_MINOR_ENCRYPTED;
    let mut w = ArchiveWriter::new_encrypted(Vec::new(), &header, Encryption::new(keys.clone(), uuid, &info)).unwrap();
    let packed = zstd::bulk::compress(data, 3).unwrap();
    let ph = PackHeader { codec: codec::ZSTD, ulen: data.len() as u64, chunks: 1, level: Some(3), dict: None };
    let pr = w.write_pack(&ph, &packed).unwrap();
    let mut chunks = ChunkTable::default();
    chunks.push(Chunk { id: keys.chunk_id(data), pack: 0, off: 0, len: data.len() as u64 });
    let snap = Snapshot {
        id: 1,
        time_ns: header.created_ns,
        comment: "Testvektor".into(),
        source: String::new(),
        entries: vec![file("hallo.txt", data, 0)],
    };
    let index = Index {
        version: 1,
        generation: 1,
        created_ns: header.created_ns,
        cdc: None,
        packs: vec![pr],
        chunks,
        snapshots: vec![snap],
    };
    w.finish(&index, 0).unwrap()
}

fn extract_all(reader: &Reader<Vec<u8>>) -> (tempfile::TempDir, archydes_decode::ExtractReport) {
    let dest = tempfile::tempdir().unwrap();
    let snap = reader.archive.index.snapshots.last().unwrap();
    let report =
        archydes_decode::extract(reader, snap, &|_| true, dest.path(), &ExtractOptions::default(), &mut |_| true)
            .unwrap();
    (dest, report)
}

#[test]
fn extract_and_verify() {
    let data = b"Inhalt, der verschluesselt war.".repeat(100);
    let bytes = build("pw", &data);
    let reader = Reader::open_with(bytes.clone(), Some("pw")).unwrap();
    let (dest, report) = extract_all(&reader);
    assert!(report.problems.is_empty(), "{:?}", report.problems.len());
    assert_eq!(fs::read(dest.path().join("hallo.txt")).unwrap(), data);
    let v = archydes_decode::verify(&reader, &mut |_, _| true).unwrap();
    assert!(v.is_ok(), "{:?}", v.problems);
    assert_eq!(v.files, 1);

    let s = archydes_decode::verify::verify_structure(&bytes).unwrap();
    assert!(s.is_ok(), "{:?}", s.problems);
    assert_eq!(s.segments, v.segments);
}

#[test]
fn structure_check_finds_damage_without_the_password() {
    let mut bytes = build("pw", b"abc");
    let reader = Reader::open_with(bytes.clone(), Some("pw")).unwrap();
    let off = reader.archive.index.packs[0].off as usize + 60;
    bytes[off] ^= 1;
    let s = archydes_decode::verify::verify_structure(&bytes).unwrap();
    assert!(s.problems.iter().any(|p| p.contains("PACK") && p.contains("hash")), "{:?}", s.problems);
    let reader = Reader::open_with(bytes, Some("pw")).unwrap();
    let v = archydes_decode::verify(&reader, &mut |_, _| true).unwrap();
    assert_eq!(v.damaged_packs, [0]);
    assert_eq!(v.damaged_files.len(), 1);
}

#[test]
fn chunk_ids_must_be_keyed() {
    // An archive whose index lists plain BLAKE3 IDs although it is encrypted.
    let uuid = [7; 16];
    let (keys, info) = Keys::create("pw", &uuid, KdfParams::MINIMUM).unwrap();
    let mut header = Header::new(flags::ENCRYPTED, uuid, 0);
    header.minor = FORMAT_MINOR_ENCRYPTED;
    let mut w = ArchiveWriter::new_encrypted(Vec::new(), &header, Encryption::new(keys, uuid, &info)).unwrap();
    let data = b"abc";
    let ph = PackHeader { codec: codec::NONE, ulen: 3, chunks: 1, level: None, dict: None };
    let pr = w.write_pack(&ph, data).unwrap();
    let mut chunks = ChunkTable::default();
    chunks.push(Chunk { id: archydes_format::hash256(data), pack: 0, off: 0, len: 3 });
    let snap = Snapshot { id: 1, time_ns: 0, comment: String::new(), source: String::new(), entries: vec![] };
    let index =
        Index { version: 1, generation: 1, created_ns: 0, cdc: None, packs: vec![pr], chunks, snapshots: vec![snap] };
    let reader = Reader::open_with(w.finish(&index, 0).unwrap(), Some("pw")).unwrap();
    let v = archydes_decode::verify(&reader, &mut |_, _| true).unwrap();
    assert!(v.problems.iter().any(|p| p.contains("do not match their IDs")), "{:?}", v.problems);
}

/// The fixed vector: written once by `write_vector`, it must open and extract forever.
#[test]
fn encrypted_vector() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors/encrypted-1.1.archy");
    let bytes = fs::read(path).unwrap();
    assert!(matches!(Reader::open(bytes.clone()), Err(Error::PasswordRequired)));
    assert!(matches!(Reader::open_with(bytes.clone(), Some("pr\u{fc}fung 1.1")), Err(Error::WrongPassword)));
    let reader = Reader::open_with(bytes, Some(PASSWORD_NFD)).unwrap();
    assert_eq!(reader.archive.footer.minor, 1);
    let (dest, report) = extract_all(&reader);
    assert!(report.problems.is_empty());
    assert_eq!(fs::read_to_string(dest.path().join("hallo.txt")).unwrap(), VECTOR_FILE);
    assert!(archydes_decode::verify(&reader, &mut |_, _| true).unwrap().is_ok());
}

/// `cargo test -p archydes-decode --test encrypted -- --ignored write_vector` writes the vector
/// again. Only for a new vector: an existing one is never replaced.
#[test]
#[ignore]
fn write_vector() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors/encrypted-1.1.archy");
    assert!(!path.exists(), "the vector exists and must stay as it is");
    fs::write(path, build(PASSWORD, VECTOR_FILE.as_bytes())).unwrap();
}

/// Seed of the `encrypted` fuzz target: its data key is the one the target uses.
#[test]
#[ignore]
fn write_fuzz_seed() {
    let uuid = *b"archydes-vector1";
    let keys = Keys::create_with("fuzz", &uuid, KdfParams::MINIMUM, [1; 16], &[0x42; 32], [2; 24]).unwrap();
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fuzz/seeds/encrypted.archy");
    fs::write(path, build_keyed(keys, &VECTOR_FILE.repeat(20).into_bytes())).unwrap();
}
