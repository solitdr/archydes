//! Hostile archives: nothing may be written outside the destination, lies about sizes are caught.

use std::fs;

use archydes_decode::{ExtractOptions, Reader};
use archydes_format::consts::codec;
use archydes_format::index::{Chunk, ChunkTable, Index};
use archydes_format::{ArchiveWriter, Entry, EntryKind, Header, PackHeader, Part, Snapshot};

fn entry(path: &str, kind: EntryKind) -> Entry {
    Entry {
        path: path.as_bytes().to_vec(),
        path_nfc: path.into(),
        kind,
        mode: 0o644,
        mtime_ns: 0,
        btime_ns: None,
        xattrs: vec![],
        target: None,
        size: 0,
        hash: None,
        recipe: None,
    }
}

fn file(path: &str, data: &[u8], chunk: u32) -> Entry {
    let mut e = entry(path, EntryKind::File);
    e.size = data.len() as u64;
    e.hash = Some(archydes_format::hash256(data));
    e.recipe = Some(vec![Part::raw(vec![chunk])]);
    e
}

fn build(data: &[u8], entries: Vec<Entry>) -> Vec<u8> {
    let mut w = ArchiveWriter::new(Vec::new(), &Header::new(0, [0; 16], 0)).unwrap();
    let ph = PackHeader { codec: codec::NONE, ulen: data.len() as u64, chunks: 1, level: None, dict: None };
    let pr = w.write_pack(&ph, data).unwrap();
    let mut chunks = ChunkTable::default();
    chunks.push(Chunk { id: archydes_format::hash256(data), pack: 0, off: 0, len: data.len() as u64 });
    let snap = Snapshot { id: 1, time_ns: 0, comment: String::new(), source: String::new(), entries };
    let index =
        Index { version: 1, generation: 1, created_ns: 0, cdc: None, packs: vec![pr], chunks, snapshots: vec![snap] };
    w.finish(&index, 0).unwrap()
}

#[test]
fn zip_slip_and_symlink_tricks_stay_inside() {
    let tmp = tempfile::tempdir().unwrap();
    let outside = tmp.path().join("outside");
    fs::create_dir(&outside).unwrap();
    let data = b"payload";
    let mut link = entry("link", EntryKind::Symlink);
    link.target = Some(outside.to_string_lossy().as_bytes().to_vec());
    let mut hard = entry("hard", EntryKind::Hardlink);
    hard.target = Some(b"../../etc/passwd".to_vec());
    let entries = vec![
        file("../evil", data, 0),
        file("/absolute", data, 0),
        file("a/../../evil2", data, 0),
        link,
        // Tries to write through the symlink above.
        file("link/through", data, 0),
        hard,
        file("ok.txt", data, 0),
    ];
    let reader = Reader::open(build(data, entries)).unwrap();
    let dest = tmp.path().join("dest");
    let snap = &reader.archive.index.snapshots[0];
    let r =
        archydes_decode::extract(&reader, snap, &|_| true, &dest, &ExtractOptions::default(), &mut |_| true).unwrap();

    assert_eq!(fs::read(dest.join("ok.txt")).unwrap(), data);
    assert!(fs::read_dir(&outside).unwrap().next().is_none(), "something was written outside");
    assert!(!tmp.path().join("evil").exists() && !tmp.path().join("evil2").exists());
    // "link/through" created a real folder "link", so the symlink could not be created.
    assert!(fs::symlink_metadata(dest.join("link")).unwrap().is_dir());
    assert_eq!(r.problems.len(), 5, "{:?}", r.problems);
}

#[test]
fn size_and_hash_lies_are_caught() {
    let data = b"0123456789";
    let mut too_small = file("small", data, 0);
    too_small.size = 4; // more data than declared: stop writing
    let mut wrong_hash = file("hash", data, 0);
    wrong_hash.hash = Some([0; 32]);
    let reader = Reader::open(build(data, vec![too_small, wrong_hash])).unwrap();
    let tmp = tempfile::tempdir().unwrap();
    let snap = &reader.archive.index.snapshots[0];
    let r = archydes_decode::extract(&reader, snap, &|_| true, tmp.path(), &ExtractOptions::default(), &mut |_| true)
        .unwrap();
    assert_eq!(r.problems.len(), 2);
    // Failed files are removed, not left half-written.
    assert!(!tmp.path().join("small").exists() && !tmp.path().join("hash").exists());

    let v = archydes_decode::verify(&reader, &mut |_, _| true).unwrap();
    assert_eq!(v.damaged_files.len(), 2);
}

#[test]
fn existing_files_are_kept_unless_overwrite() {
    let data = b"new";
    let reader = Reader::open(build(data, vec![file("f", data, 0)])).unwrap();
    let tmp = tempfile::tempdir().unwrap();
    fs::write(tmp.path().join("f"), b"old").unwrap();
    let snap = &reader.archive.index.snapshots[0];
    let r = archydes_decode::extract(&reader, snap, &|_| true, tmp.path(), &ExtractOptions::default(), &mut |_| true)
        .unwrap();
    assert_eq!(r.problems.len(), 1);
    assert_eq!(fs::read(tmp.path().join("f")).unwrap(), b"old");
    let opts = ExtractOptions { overwrite: true, ..Default::default() };
    archydes_decode::extract(&reader, snap, &|_| true, tmp.path(), &opts, &mut |_| true).unwrap();
    assert_eq!(fs::read(tmp.path().join("f")).unwrap(), b"new");
}

#[test]
fn every_single_byte_flip_is_detected_or_harmless() {
    // Flipping any byte must never make extraction return wrong data silently.
    let data = b"some file content that is long enough";
    let bytes = build(data, vec![file("f", data, 0)]);
    for i in 0..bytes.len() {
        let mut b = bytes.clone();
        b[i] ^= 0x01;
        let Ok(reader) = Reader::open(b) else { continue };
        let Some(snap) = reader.archive.index.snapshots.first() else { continue };
        let Some(e) = snap.entries.first() else { continue };
        let mut out = Vec::new();
        if reader.write_file(e, &mut out).is_ok() {
            assert_eq!(out, data, "flip at {i} produced wrong data");
        }
    }
}

/// Rebuilds a PREFLATE part from a fuzz input `[kind, len (24 bits), plain, corrections]`.
fn preflate_from_fuzz_input(data: &[u8], corrections_len: Option<usize>) -> archydes_format::Result<()> {
    use archydes_decode::transform::{preflate_part_params, rebuild_part};
    let rest = &data[4..];
    let split = ((data[1] as usize) << 16 | (data[2] as usize) << 8 | data[3] as usize).min(rest.len());
    let (plain, corrections) = rest.split_at(split);
    let corrections = &corrections[..corrections_len.unwrap_or(corrections.len()).min(corrections.len())];
    let part = archydes_format::Part {
        transform: archydes_format::consts::transform::PREFLATE,
        params: preflate_part_params(),
        inputs: vec![vec![], vec![]],
    };
    let inputs = [plain, corrections];
    rebuild_part(&part, &mut |k, s| s(inputs[k]), &mut |_| Ok(()))
}

/// Found by fuzz target `transform`: corrections that predict deflate blocks without end used
/// to grow memory without limit inside preflate-rs (bounded in the fork, FORK.md).
#[test]
fn preflate_endless_blocks_are_an_error() {
    let e = preflate_from_fuzz_input(include_bytes!("vectors/hostile-preflate-endless.bin"), None).unwrap_err();
    assert!(e.to_string().contains("too many deflate blocks"), "{e}");
}

/// Found by fuzz target `transform`: token and tree sizes taken from the corrections (up to
/// 2^32) used to size allocations. Fuzz builds of bitcode accept trailing bytes, so every
/// shortened version of the corrections is tried as well.
#[test]
fn preflate_huge_counts_are_an_error() {
    let data = include_bytes!("vectors/hostile-preflate-huge-tree.bin");
    for n in 0..data.len() {
        assert!(preflate_from_fuzz_input(data, Some(n)).is_err(), "{n}");
    }
}

/// Found by fuzz target `transform`: a damaged JPEG XL file made jxl-oxide panic.
#[test]
fn damaged_jxl_is_an_error() {
    let data = include_bytes!("vectors/hostile-jxl-panic.bin");
    let r = archydes_decode::transform::jpeg_from_jxl(&data[4..], &mut |_| Ok(()));
    assert!(r.is_err());
}
