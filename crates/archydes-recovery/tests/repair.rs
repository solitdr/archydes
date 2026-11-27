//! Repair with recovery data: random damage up to the capacity is repaired bit-exactly, damage
//! beyond it is reported and the rest is still rebuilt.

use std::fs::{self, File, OpenOptions};
use std::io::Cursor;
use std::path::Path;

use archydes_format::consts::{FORMAT_MAJOR, FORMAT_MINOR, codec, flags, segment_type};
use archydes_format::index::{Chunk, ChunkTable, Index};
use archydes_format::{Archive, ArchiveWriter, Footer, Header, PackHeader};
use archydes_recovery::{Layout, SLICE};

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }

    fn bytes(&mut self, len: usize) -> Vec<u8> {
        (0..len).map(|_| self.next() as u8).collect()
    }
}

/// An archive with uncompressed packs of `pack_bytes` each and `permille` recovery data.
fn build(packs: usize, pack_bytes: usize, permille: u32) -> Vec<u8> {
    let mut rng = Rng(0x1234_5678);
    let header = Header::new(flags::RECOVERY, [9; 16], 1);
    let mut w = ArchiveWriter::new(Cursor::new(Vec::new()), &header).unwrap();
    let mut chunks = ChunkTable::default();
    let mut refs = Vec::new();
    for p in 0..packs {
        let data = rng.bytes(pack_bytes);
        let ph = PackHeader { codec: codec::NONE, ulen: data.len() as u64, chunks: 1, level: None, dict: None };
        refs.push(w.write_pack(&ph, &data).unwrap());
        chunks.push(Chunk { id: archydes_format::hash256(&data), pack: p as u32, off: 0, len: data.len() as u64 });
    }
    let index = Index { version: 1, generation: 1, created_ns: 1, cdc: None, packs: refs, chunks, snapshots: vec![] };
    let (index_offset, index_copy_offset) = w.write_index(&index).unwrap();
    let covered = w.get_mut().get_ref().clone();
    let layout = Layout::new(0, w.offset(), permille, 0);
    let (recovery_offset, _) = w
        .write_segment_with(segment_type::RECOVERY, 0, layout.payload_len(), |out| {
            archydes_recovery::write_payload(&covered, &layout, 2, out, &mut |_, _| true)
        })
        .unwrap();
    let footer = Footer {
        major: FORMAT_MAJOR,
        minor: FORMAT_MINOR,
        flags: flags::RECOVERY,
        index_offset,
        index_copy_offset,
        recovery_offset,
        generation: 1,
        key_info_offset: 0,
    };
    w.write_footer(&footer).unwrap().into_inner()
}

fn repair_bytes(dir: &Path, bytes: &[u8]) -> (archydes_recovery::RepairReport, Vec<u8>) {
    let p = dir.join("x.archy");
    fs::write(&p, bytes).unwrap();
    let f = OpenOptions::new().read(true).write(true).open(&p).unwrap();
    let r = archydes_recovery::repair(&f, 2).unwrap();
    drop(f);
    (r, fs::read(&p).unwrap())
}

/// Damages one byte in each of the given data slices; returns the positions.
fn damage_slices(bytes: &mut [u8], layout: &Layout, slices: &[u64], rng: &mut Rng) -> Vec<u64> {
    let mut at = Vec::new();
    for &s in slices {
        let (a, b) = layout.slice_range(s);
        let p = a + rng.below(b - a);
        bytes[p as usize] ^= 1 + rng.below(255) as u8;
        at.push(p);
    }
    at
}

fn layout_of(bytes: &Vec<u8>) -> Layout {
    archydes_recovery::locate(bytes).expect("recovery data")
}

#[test]
fn intact_archive_is_clean_and_opens() {
    let a = build(3, 300_000, 50);
    let l = layout_of(&a);
    let s = archydes_recovery::check(&a, &l, 2).unwrap();
    assert!(s.is_clean(), "{s:?}");
    let archive = Archive::open(a).unwrap();
    assert!(archive.warnings.is_empty(), "{:?}", archive.warnings);
    assert_ne!(archive.footer.recovery_offset, 0);
}

#[test]
fn random_damage_up_to_capacity_is_repaired() {
    let tmp = tempfile::tempdir().unwrap();
    let original = build(8, 1 << 20, 50);
    let layout = layout_of(&original);
    assert_eq!(layout.groups.len(), 1);
    let r = layout.groups[0].1 as u64;
    let n = layout.data_slices();
    for seed in 1..=20u64 {
        let mut rng = Rng(seed * 7919);
        // r distinct slices, anywhere in the covered range (header, packs, index …).
        let mut slices = Vec::new();
        while (slices.len() as u64) < r {
            let s = rng.below(n);
            if !slices.contains(&s) {
                slices.push(s);
            }
        }
        let mut bytes = original.clone();
        damage_slices(&mut bytes, &layout, &slices, &mut rng);
        let (report, repaired) = repair_bytes(tmp.path(), &bytes);
        assert!(report.complete(), "seed {seed}: {report:?}");
        assert_eq!(report.repaired_slices, r);
        assert!(repaired == original, "seed {seed}: not bit-exact");
    }
}

#[test]
fn damage_beyond_capacity_is_reported() {
    let tmp = tempfile::tempdir().unwrap();
    let original = build(8, 1 << 20, 50);
    let layout = layout_of(&original);
    let r = layout.groups[0].1 as u64;
    let mut rng = Rng(42);
    let slices: Vec<u64> = (10..10 + r + 1).collect();
    let mut bytes = original.clone();
    let hits = damage_slices(&mut bytes, &layout, &slices, &mut rng);
    let status = archydes_recovery::check(&bytes, &layout, 2).unwrap();
    assert_eq!(status.damaged_data, slices);
    assert!(!status.repairable());

    let (report, repaired) = repair_bytes(tmp.path(), &bytes);
    assert!(!report.complete());
    assert_eq!(report.unrepaired.len() as u64, r + 1);
    assert_eq!(report.unrepaired[0], layout.slice_range(10));
    assert!(!report.recovery_rewritten, "recovery data must not be rebuilt over damaged data");
    // Nothing else was touched.
    assert_eq!(repaired, bytes);
    // The archive still opens: only the packs in the damaged range are lost.
    let a = Archive::open(repaired).unwrap();
    let bad: Vec<usize> = (0..a.index.packs.len()).filter(|&i| a.read_pack(i).is_err()).collect();
    assert!(!bad.is_empty());
    for (i, p) in a.index.packs.iter().enumerate() {
        let (_, sh) = (0, a.walk());
        let end = sh
            .iter()
            .find_map(|w| match w {
                archydes_format::WalkItem::Segment { offset, header } if *offset == p.off => header.end(*offset),
                _ => None,
            })
            .unwrap_or(p.off + 40 + p.clen + 64);
        let touched = hits.iter().any(|&h| h >= p.off && h < end);
        assert_eq!(bad.contains(&i), touched, "pack {i}");
    }
}

#[test]
fn burst_across_groups_is_repaired() {
    // More than MAX_GROUP slices, so there are several interleaved groups.
    let tmp = tempfile::tempdir().unwrap();
    let original = build(5, 15 << 20, 50);
    let layout = layout_of(&original);
    assert!(layout.groups.len() >= 2, "{:?}", layout.groups.len());
    // One contiguous burst almost as long as all parity together.
    let burst = layout.parity_slices() - layout.groups.len() as u64;
    let start = layout.slice_range(100).0 as usize;
    let mut bytes = original.clone();
    let mut rng = Rng(5);
    for b in &mut bytes[start..start + burst as usize * SLICE] {
        *b = rng.next() as u8;
    }
    let (report, repaired) = repair_bytes(tmp.path(), &bytes);
    assert!(report.complete(), "{report:?}");
    assert_eq!(report.repaired_slices, burst);
    assert!(repaired == original);
}

#[test]
fn damaged_footer_head_and_parity_are_rebuilt() {
    // Each head has two copies; one of them has to survive.
    let tmp = tempfile::tempdir().unwrap();
    let original = build(4, 1 << 20, 50);
    let layout = layout_of(&original);
    let len = original.len();
    let payload = layout.end as usize + 40;
    for front in [true, false] {
        let mut bytes = original.clone();
        let footer = if front { len - 64 } else { len - 100 };
        for b in &mut bytes[footer..] {
            *b = 0;
        }
        if front {
            bytes[payload + 10] ^= 0xff;
        }
        // One parity slice and one data slice.
        bytes[payload + 200] ^= 0xff;
        bytes[5000] ^= 0x10;
        let (report, repaired) = repair_bytes(tmp.path(), &bytes);
        assert!(report.complete(), "{report:?}");
        assert!(report.recovery_rewritten && report.footer_rewritten);
        assert!(repaired == original, "front {front}: not bit-exact");
    }
}

#[test]
fn missing_footer_is_rebuilt() {
    let tmp = tempfile::tempdir().unwrap();
    let original = build(2, 500_000, 50);
    let (report, repaired) = repair_bytes(tmp.path(), &original[..original.len() - 64]);
    assert!(report.footer_rewritten);
    assert!(repaired == original);
}

#[test]
fn no_recovery_data_is_an_error() {
    let tmp = tempfile::tempdir().unwrap();
    let p = tmp.path().join("none.archy");
    let mut w = ArchiveWriter::new(Vec::new(), &Header::new(0, [1; 16], 1)).unwrap();
    let ph = PackHeader { codec: codec::NONE, ulen: 3, chunks: 1, level: None, dict: None };
    let pr = w.write_pack(&ph, b"abc").unwrap();
    let mut chunks = ChunkTable::default();
    chunks.push(Chunk { id: archydes_format::hash256(b"abc"), pack: 0, off: 0, len: 3 });
    let index =
        Index { version: 1, generation: 1, created_ns: 1, cdc: None, packs: vec![pr], chunks, snapshots: vec![] };
    fs::write(&p, w.finish(&index, 0).unwrap()).unwrap();
    let f = OpenOptions::new().read(true).write(true).open(&p).unwrap();
    assert!(archydes_recovery::repair(&f, 1).is_err());
    assert!(archydes_recovery::locate(&File::open(&p).unwrap()).is_none());
}

/// Encrypted archives are repaired without the password (SPEC A11): the recovery data covers
/// the ciphertext, and a lost footer is rebuilt with its KEY_INFO pointer.
#[test]
fn encrypted_archive_is_repaired_without_the_password() {
    use archydes_format::{Encryption, KdfParams, Keys};
    let uuid = [3; 16];
    let (keys, info) = Keys::create("pw", &uuid, KdfParams::MINIMUM).unwrap();
    let mut header = Header::new(flags::ENCRYPTED | flags::RECOVERY, uuid, 1);
    header.minor = archydes_format::consts::FORMAT_MINOR_ENCRYPTED;
    let mut w =
        ArchiveWriter::new_encrypted(Cursor::new(Vec::new()), &header, Encryption::new(keys.clone(), uuid, &info))
            .unwrap();
    let mut rng = Rng(77);
    let data = rng.bytes(700_000);
    let ph = PackHeader { codec: codec::NONE, ulen: data.len() as u64, chunks: 1, level: None, dict: None };
    let pr = w.write_pack(&ph, &data).unwrap();
    let mut chunks = ChunkTable::default();
    chunks.push(Chunk { id: keys.chunk_id(&data), pack: 0, off: 0, len: data.len() as u64 });
    let index =
        Index { version: 1, generation: 1, created_ns: 1, cdc: None, packs: vec![pr], chunks, snapshots: vec![] };
    let (index_offset, index_copy_offset) = w.write_index(&index).unwrap();
    let covered = w.get_mut().get_ref().clone();
    let layout = Layout::new(0, w.offset(), 50, 0);
    let (recovery_offset, _) = w
        .write_segment_with(segment_type::RECOVERY, 0, layout.payload_len(), |out| {
            archydes_recovery::write_payload(&covered, &layout, 2, out, &mut |_, _| true)
        })
        .unwrap();
    let footer = Footer {
        major: FORMAT_MAJOR,
        minor: w.minor(),
        flags: header.flags,
        index_offset,
        index_copy_offset,
        recovery_offset,
        generation: 1,
        key_info_offset: w.key_info_offset(),
    };
    let original = w.write_footer(&footer).unwrap().into_inner();
    assert!(Archive::open_with(original.clone(), Some("pw")).unwrap().warnings.is_empty());

    let tmp = tempfile::tempdir().unwrap();
    let mut damaged = original[..original.len() - 64].to_vec();
    damaged[pr.off as usize + 5000] ^= 0x55;
    let (report, repaired) = repair_bytes(tmp.path(), &damaged);
    assert!(report.complete() && report.footer_rewritten, "{report:?}");
    assert!(repaired == original, "not bit-exact");
}

/// A rebuilt footer has the flags the packer writes: "several snapshots" comes from the index,
/// not from the file header, which shows the state at creation (SPEC A5.1, A9).
#[test]
fn rebuilt_footer_keeps_several_snapshots() {
    let tmp = tempfile::tempdir().unwrap();
    let vector = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testvectors/generations-interrupted.archy");
    let bytes = fs::read(vector).unwrap();
    let archive = Archive::open(bytes.clone()).unwrap();
    assert_eq!(archive.index.snapshots.len(), 2);
    assert_ne!(archive.footer.flags & flags::MULTIPLE_SNAPSHOTS, 0);
    let generation_2 = &bytes[..(archive.footer_offset + 64) as usize];
    let (report, repaired) = repair_bytes(tmp.path(), &generation_2[..generation_2.len() - 64]);
    assert!(report.footer_rewritten, "{report:?}");
    assert!(repaired == generation_2, "the rebuilt footer differs from the one the packer wrote");
}
