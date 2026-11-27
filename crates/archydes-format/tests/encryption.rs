//! Encrypted archives (SPEC A11): writing, opening, wrong passwords, damage and mixed segments.

use archydes_format::consts::{FORMAT_MINOR_ENCRYPTED, codec, flags, segment_flags, segment_type};
use archydes_format::index::{Chunk, ChunkTable, Index};
use archydes_format::reader::WalkItem;
use archydes_format::{Archive, ArchiveWriter, Encryption, Error, Header, KdfParams, Keys, PackHeader, SegmentHeader};

const UUID: [u8; 16] = [4; 16];
const PASSWORD: &str = "korrekt Pferd Batterie";

fn header() -> Header {
    let mut h = Header::new(flags::ENCRYPTED, UUID, 5);
    h.minor = FORMAT_MINOR_ENCRYPTED;
    h
}

fn encryption() -> Encryption {
    let (keys, info) = Keys::create(PASSWORD, &UUID, KdfParams::MINIMUM).unwrap();
    Encryption::new(keys, UUID, &info)
}

fn index(w: &mut ArchiveWriter<Vec<u8>>, data: &[u8], generation: u64) -> Index {
    let ph = PackHeader { codec: codec::NONE, ulen: data.len() as u64, chunks: 1, level: None, dict: None };
    let pr = w.write_pack(&ph, data).unwrap();
    let id = w.encryption().unwrap().keys.chunk_id(data);
    let mut chunks = ChunkTable::default();
    chunks.push(Chunk { id, pack: 0, off: 0, len: data.len() as u64 });
    Index { version: 1, generation, created_ns: 5, cdc: None, packs: vec![pr], chunks, snapshots: vec![] }
}

fn build_with(e: Encryption) -> Vec<u8> {
    let mut w = ArchiveWriter::new_encrypted(Vec::new(), &header(), e).unwrap();
    let i = index(&mut w, b"geheime Daten", 1);
    w.finish(&i, 0).unwrap()
}

fn build() -> Vec<u8> {
    build_with(encryption())
}

fn segments(bytes: &[u8]) -> Vec<(u64, SegmentHeader)> {
    archydes_format::walk(bytes)
        .into_iter()
        .filter_map(|w| match w {
            WalkItem::Segment { offset, header } => Some((offset, header)),
            _ => None,
        })
        .collect()
}

#[test]
fn round_trip_and_layout() {
    let bytes = build();
    let a = Archive::open_with(bytes.clone(), Some(PASSWORD)).unwrap();
    assert!(a.warnings.is_empty(), "{:?}", a.warnings);
    assert!(a.is_encrypted());
    assert_eq!(a.footer.minor, 1);
    assert_ne!(a.footer.flags & flags::ENCRYPTED, 0);
    let (_, data) = a.read_pack(0).unwrap();
    assert_eq!(data, b"geheime Daten");
    assert_eq!(a.chunk_id(b"geheime Daten"), a.index.chunks.get(0).id);
    assert_ne!(a.chunk_id(b"x"), archydes_format::hash256(b"x"));

    let segs = segments(&bytes);
    let kinds: Vec<_> = segs.iter().map(|(_, h)| h.kind).collect();
    use segment_type::*;
    assert_eq!(kinds, [FORMAT_INFO, KEY_INFO, PACK, KEY_INFO, INDEX, INDEX_COPY]);
    for (_, h) in &segs {
        assert_eq!(h.is_encrypted(), matches!(h.kind, PACK | INDEX | INDEX_COPY), "{}", segment_type::name(h.kind));
    }
    assert_eq!(a.footer.key_info_offset, segs[3].0);
    // INDEX_COPY holds the same ciphertext as INDEX.
    assert_eq!(segs[4].1.payload_hash, segs[5].1.payload_hash);
    // The plaintext does not appear anywhere.
    assert!(!bytes.windows(7).any(|w| w == b"geheime"));
    let info = std::str::from_utf8(&bytes[104..104 + segs[0].1.payload_len as usize]).unwrap();
    assert!(info.contains("format 1.1"), "{info}");
}

#[test]
fn password_is_needed_and_checked() {
    let bytes = build();
    assert!(matches!(Archive::open(bytes.clone()), Err(Error::PasswordRequired)));
    assert!(matches!(Archive::open_with(bytes.clone(), Some("falsch")), Err(Error::WrongPassword)));
    assert!(matches!(Archive::open_with(bytes, Some("")), Err(Error::WrongPassword)));
}

#[test]
fn unencrypted_archives_ignore_a_password() {
    let mut w = ArchiveWriter::new(Vec::new(), &Header::new(0, UUID, 5)).unwrap();
    let data = b"offen";
    let ph = PackHeader { codec: codec::NONE, ulen: 5, chunks: 1, level: None, dict: None };
    let pr = w.write_pack(&ph, data).unwrap();
    let mut chunks = ChunkTable::default();
    chunks.push(Chunk { id: archydes_format::hash256(data), pack: 0, off: 0, len: 5 });
    let i = Index { version: 1, generation: 1, created_ns: 5, cdc: None, packs: vec![pr], chunks, snapshots: vec![] };
    let bytes = w.finish(&i, 0).unwrap();
    let a = Archive::open_with(bytes, Some("egal")).unwrap();
    assert!(!a.is_encrypted());
    assert_eq!(a.footer.minor, 0);
    assert_eq!(a.footer.key_info_offset, 0);
    assert!(ArchiveWriter::new(Vec::new(), &header()).is_err(), "an encrypted header needs the keys");
}

#[test]
fn tampered_ciphertext_is_damage() {
    let bytes = build();
    let segs = segments(&bytes);
    let (pack_off, pack) = segs[2];
    // Flip a ciphertext byte and fix the segment hash, so only the tag can notice.
    let mut b = bytes.clone();
    let p = (pack_off + 40 + 30) as usize;
    b[p] ^= 1;
    let payload = &b[(pack_off + 40) as usize..(pack_off + 40 + pack.payload_len) as usize];
    let fixed = SegmentHeader { payload_hash: archydes_format::hash128(payload), ..pack };
    b[pack_off as usize..pack_off as usize + 40].copy_from_slice(&fixed.encode());
    let a = Archive::open_with(b, Some(PASSWORD)).unwrap();
    let err = a.read_pack(0).unwrap_err().to_string();
    assert!(err.contains("authentication tag"), "{err}");
}

#[test]
fn damaged_index_falls_back_to_copy() {
    let mut bytes = build();
    let a = Archive::open_with(bytes.clone(), Some(PASSWORD)).unwrap();
    bytes[a.footer.index_offset as usize + 50] ^= 0xff;
    let a = Archive::open_with(bytes, Some(PASSWORD)).unwrap();
    assert!(a.warnings.iter().any(|w| w.contains("INDEX_COPY")), "{:?}", a.warnings);
}

#[test]
fn key_info_is_found_when_one_copy_is_damaged() {
    let bytes = build();
    let segs = segments(&bytes);
    // The generation's copy (footer pointer) damaged: the first one is used.
    let mut b = bytes.clone();
    b[(segs[3].0 + 45) as usize] ^= 0xff;
    assert!(Archive::open_with(b, Some(PASSWORD)).is_ok());
    // The first one damaged: the footer's.
    let mut b = bytes.clone();
    b[(segs[1].0 + 45) as usize] ^= 0xff;
    assert!(Archive::open_with(b.clone(), Some(PASSWORD)).is_ok());
    // First one and footer damaged: the backward search finds the copy.
    let n = b.len();
    b[n - 20] ^= 0xff;
    let a = Archive::open_with(b, Some(PASSWORD)).unwrap();
    assert!(!a.warnings.is_empty());
}

#[test]
fn mixed_segments_are_rejected() {
    // A PACK without the encrypted flag in an encrypted archive.
    let e = encryption();
    let mut w = ArchiveWriter::new_encrypted(Vec::new(), &header(), e.clone()).unwrap();
    let data = b"klar";
    let ph = PackHeader { codec: codec::NONE, ulen: 4, chunks: 1, level: None, dict: None };
    let prefix = ph.encode_prefix();
    let (off, sh) = w.write_segment(segment_type::PACK, segment_flags::CRITICAL, &[&prefix, data]).unwrap();
    let mut chunks = ChunkTable::default();
    chunks.push(Chunk { id: e.keys.chunk_id(data), pack: 0, off: 0, len: 4 });
    let pr = archydes_format::PackRef { off, clen: 4, ulen: 4, codec: codec::NONE, hash: sh.payload_hash };
    let i = Index { version: 1, generation: 1, created_ns: 5, cdc: None, packs: vec![pr], chunks, snapshots: vec![] };
    let bytes = w.finish(&i, 0).unwrap();
    let a = Archive::open_with(bytes, Some(PASSWORD)).unwrap();
    let err = a.read_pack(0).unwrap_err().to_string();
    assert!(err.contains("not encrypted"), "{err}");

    // An encrypted-flag segment in an unencrypted archive.
    let mut w = ArchiveWriter::new(Vec::new(), &Header::new(0, UUID, 5)).unwrap();
    let (off, sh) = w
        .write_segment(segment_type::PACK, segment_flags::CRITICAL | segment_flags::ENCRYPTED, &[&prefix, data])
        .unwrap();
    let mut chunks = ChunkTable::default();
    chunks.push(Chunk { id: archydes_format::hash256(data), pack: 0, off: 0, len: 4 });
    let pr = archydes_format::PackRef { off, clen: 4, ulen: 4, codec: codec::NONE, hash: sh.payload_hash };
    let i = Index { version: 1, generation: 1, created_ns: 5, cdc: None, packs: vec![pr], chunks, snapshots: vec![] };
    let a = Archive::open(w.finish(&i, 0).unwrap()).unwrap();
    assert!(a.read_pack(0).unwrap_err().to_string().contains("is encrypted"));
}

#[test]
fn encrypted_header_with_format_1_0_is_rejected() {
    let mut bytes = build();
    let mut h = header();
    h.minor = 0;
    bytes[..64].copy_from_slice(&h.encode());
    assert!(matches!(Archive::open_with(bytes, Some(PASSWORD)), Err(Error::Corrupt(_))));
}

#[test]
fn appended_generation_repeats_key_info() {
    let e = encryption();
    let first = build_with(e.clone());
    let a = Archive::open_with(first.clone(), Some(PASSWORD)).unwrap();
    let mut w = ArchiveWriter::append_encrypted(first, a.file_size(), a.encryption().unwrap());
    let i = index(&mut w, b"zweite Generation", 2);
    let bytes = w.finish(&i, 0).unwrap();
    let a = Archive::open_with(bytes.clone(), Some(PASSWORD)).unwrap();
    assert_eq!(a.footer.generation, 2);
    let segs = segments(&bytes);
    let infos: Vec<_> = segs.iter().filter(|(_, h)| h.kind == segment_type::KEY_INFO).collect();
    assert_eq!(infos.len(), 3);
    assert!(infos.iter().all(|(_, h)| h.payload_hash == infos[0].1.payload_hash), "all KEY_INFO are equal");
    assert_eq!(a.footer.key_info_offset, infos[2].0);
}

#[test]
fn reopening_with_keys_skips_the_password() {
    let bytes = build();
    let a = Archive::open_with(bytes.clone(), Some(PASSWORD)).unwrap();
    let again = Archive::open_with_keys(bytes.clone(), a.keys().unwrap().clone()).unwrap();
    assert_eq!(again.read_pack(0).unwrap().1, b"geheime Daten");
    assert_eq!(again.encryption().unwrap().key_info, a.encryption().unwrap().key_info);
    assert!(Archive::open_with_keys(bytes, Keys::from_dek([0; 32])).is_err());
}

/// An append to an encrypted archive that was interrupted before its footer: the remains hold
/// the KEY_INFO copy of the new generation and are not damage (SPEC A10, A11).
#[test]
fn interrupted_encrypted_append_is_not_damage() {
    let e = encryption();
    let first = build_with(e.clone());
    let a = Archive::open_with(first.clone(), Some(PASSWORD)).unwrap();
    let mut w = ArchiveWriter::append_encrypted(first.clone(), a.file_size(), a.encryption().unwrap());
    let i = index(&mut w, b"zweite Generation", 2);
    let full = w.finish(&i, 0).unwrap();
    let key_info = segments(&full).into_iter().rfind(|(_, h)| h.kind == segment_type::KEY_INFO).unwrap();
    // Cut inside the footer, and right after the KEY_INFO copy.
    for cut in [full.len() - 30, key_info.1.end(key_info.0).unwrap() as usize + 10] {
        let a = Archive::open_with(full[..cut].to_vec(), Some(PASSWORD)).unwrap();
        assert!(a.warnings.is_empty(), "cut at {cut}: {:?}", a.warnings);
        assert_eq!(a.footer.generation, 1);
        assert_eq!(a.interrupted, (cut - first.len()) as u64);
    }
}
