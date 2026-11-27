use archydes_format::consts::{codec, segment_type};
use archydes_format::index::{Chunk, ChunkTable, Index};
use archydes_format::{Archive, ArchiveWriter, Header, PackHeader};

fn build() -> Vec<u8> {
    let mut w = ArchiveWriter::new(Vec::new(), &Header::new(0, [1; 16], 5)).unwrap();
    let data = b"hello world";
    let ph = PackHeader { codec: codec::NONE, ulen: data.len() as u64, chunks: 1, level: None, dict: None };
    let pr = w.write_pack(&ph, data).unwrap();
    let mut chunks = ChunkTable::default();
    chunks.push(Chunk { id: archydes_format::hash256(data), pack: 0, off: 0, len: data.len() as u64 });
    let index =
        Index { version: 1, generation: 1, created_ns: 5, cdc: None, packs: vec![pr], chunks, snapshots: vec![] };
    w.finish(&index, 0).unwrap()
}

#[test]
fn open_and_read_pack() {
    let a = Archive::open(build()).unwrap();
    assert!(a.warnings.is_empty());
    let (ph, data) = a.read_pack(0).unwrap();
    assert_eq!(ph.ulen, 11);
    assert_eq!(data, b"hello world");
    let kinds: Vec<_> = a
        .walk()
        .into_iter()
        .filter_map(|w| match w {
            archydes_format::reader::WalkItem::Segment { header, .. } => Some(header.kind),
            _ => None,
        })
        .collect();
    assert_eq!(kinds, [segment_type::FORMAT_INFO, segment_type::PACK, segment_type::INDEX, segment_type::INDEX_COPY]);
}

#[test]
fn damaged_footer_uses_backward_search() {
    let mut bytes = build();
    let n = bytes.len();
    bytes[n - 10] ^= 0xff;
    let a = Archive::open(bytes).unwrap();
    assert!(!a.warnings.is_empty());
    assert_eq!(a.index.packs.len(), 1);
}

#[test]
fn damaged_index_uses_copy() {
    let mut bytes = build();
    let a = Archive::open(bytes.clone()).unwrap();
    let off = a.footer.index_offset as usize + 45;
    bytes[off] ^= 0xff;
    let a = Archive::open(bytes).unwrap();
    assert!(a.warnings.iter().any(|w| w.contains("INDEX_COPY")));
}

#[test]
fn truncated_after_footer_still_opens_last_generation() {
    // Garbage appended after the footer (an interrupted append): the old footer is found.
    let mut bytes = build();
    bytes.extend_from_slice(b"AHSG partial segment of an aborted append");
    let a = Archive::open(bytes).unwrap();
    assert_eq!(a.index.generation, 1);
}

#[test]
fn garbage_is_rejected() {
    assert!(Archive::open(vec![0u8; 10]).is_err());
    assert!(Archive::open(b"\x89ARCH\r\n\x1a".repeat(20)).is_err());
}

/// A footer counts only where it follows the last segment of its generation. In this test
/// vector the parity of the interrupted RECOVERY segment is a verbatim copy of the second
/// generation's footer, 1632 bytes behind the real one (SPEC A5.4, A10).
#[test]
fn footer_copy_in_recovery_parity_is_not_the_footer() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testvectors/generations-interrupted.archy");
    let bytes = std::fs::read(path).unwrap();
    let a = Archive::open(bytes.clone()).unwrap();
    assert!(a.warnings.is_empty(), "{:?}", a.warnings);
    assert_eq!(a.footer.generation, 2);
    assert_eq!(a.footer_offset, 137_942);
    assert_eq!(a.interrupted, bytes.len() as u64 - 138_006);
}
