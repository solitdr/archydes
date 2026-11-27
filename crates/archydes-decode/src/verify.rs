//! Verifying an archive: every segment, every pack, every chunk and every file of every
//! snapshot. Reports which files are affected by damage.

use std::collections::HashSet;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;

use archydes_format::consts::segment_type;
use archydes_format::reader::WalkItem;
use archydes_format::{EntryKind, Error, ReadAt, Result};

use crate::reader::{Discard, Reader};

#[derive(Debug, Clone)]
pub struct DamagedFile {
    pub snapshot: u64,
    pub path: String,
    pub reason: String,
}

#[derive(Debug, Default, Clone)]
pub struct VerifyReport {
    pub segments: usize,
    pub packs: usize,
    pub chunks: usize,
    pub files: u64,
    pub bytes: u64,
    /// Problems with the structure (segments, footers, index).
    pub problems: Vec<String>,
    pub damaged_packs: Vec<u32>,
    pub damaged_files: Vec<DamagedFile>,
    /// Remains of an interrupted append after the last footer (not part of the archive).
    pub interrupted: u64,
}

impl VerifyReport {
    pub fn is_ok(&self) -> bool {
        self.problems.is_empty() && self.damaged_packs.is_empty() && self.damaged_files.is_empty()
    }
}

/// Checks what can be checked without the password of an encrypted archive (or without
/// opening it at all): every segment against its payload hash, unknown critical segments and
/// damaged areas. Recovery data is checked separately (`archydes_recovery::check`).
pub fn verify_structure<R: ReadAt + ?Sized>(src: &R) -> Result<VerifyReport> {
    let mut report = VerifyReport::default();
    let mut hb = [0u8; archydes_format::consts::HEADER_LEN];
    src.read_exact_at(&mut hb, 0)?;
    archydes_format::Header::decode(&hb)?;
    let mut buf = vec![0u8; 1 << 20];
    let mut footers = 0;
    for item in archydes_format::walk(src) {
        match item {
            WalkItem::Segment { offset, header } => {
                report.segments += 1;
                if !segment_type::is_known(header.kind) && header.kind < 0x8000 && header.is_critical() {
                    report.problems.push(format!("unknown critical segment type {:#06x} at {offset}", header.kind));
                }
                let mut hasher = blake3::Hasher::new();
                let mut pos = offset + archydes_format::consts::SEGMENT_HEADER_LEN as u64;
                let mut left = header.payload_len;
                while left > 0 {
                    let n = left.min(buf.len() as u64) as usize;
                    src.read_exact_at(&mut buf[..n], pos)?;
                    hasher.update(&buf[..n]);
                    pos += n as u64;
                    left -= n as u64;
                }
                if hasher.finalize().as_bytes()[..16] != header.payload_hash {
                    report
                        .problems
                        .push(format!("{} segment at {offset}: hash mismatch", segment_type::name(header.kind)));
                }
            }
            WalkItem::Footer { .. } => footers += 1,
            WalkItem::Damaged { offset } => report.problems.push(format!("damaged area at offset {offset}")),
        }
    }
    if footers == 0 {
        report.problems.push("no readable footer".into());
    }
    Ok(report)
}

/// `progress(done, total)` in bytes of uncompressed data; returning `false` cancels.
pub fn verify<R: ReadAt>(reader: &Reader<R>, progress: &mut dyn FnMut(u64, u64) -> bool) -> Result<VerifyReport> {
    let archive = &reader.archive;
    let index = &archive.index;
    let mut report = VerifyReport {
        packs: index.packs.len(),
        chunks: index.chunks.len(),
        interrupted: archive.interrupted,
        ..Default::default()
    };
    report.problems.extend(archive.warnings.iter().cloned());

    // 1. Structure.
    for item in archive.walk() {
        match item {
            WalkItem::Segment { offset, header } => {
                report.segments += 1;
                let known = segment_type::is_known(header.kind) || header.kind >= 0x8000;
                if !known && header.is_critical() {
                    report.problems.push(format!("unknown critical segment type {:#06x} at {offset}", header.kind));
                }
            }
            WalkItem::Footer { .. } => {}
            WalkItem::Damaged { offset } => report.problems.push(format!("damaged area at offset {offset}")),
        }
        if let WalkItem::Segment { offset, header } = item
            && archive.is_encrypted()
            && header.kind == segment_type::PLAIN_TOC
        {
            report.problems.push(format!("PLAIN_TOC at {offset} in an encrypted archive"));
        }
    }
    if let Some(encryption) = archive.encryption() {
        let off = archive.footer.key_info_offset;
        match archive.read_segment(off, segment_type::KEY_INFO, archive.footer_offset) {
            Ok((_, payload)) if payload == encryption.key_info => {}
            Ok(_) => report.problems.push(format!("KEY_INFO at {off} differs from the one in use")),
            Err(e) => report.problems.push(format!("KEY_INFO of this generation: {e}")),
        }
    }
    for (name, off, kind) in [
        ("INDEX", archive.footer.index_offset, segment_type::INDEX),
        ("INDEX_COPY", archive.footer.index_copy_offset, segment_type::INDEX_COPY),
    ] {
        if off != 0
            && let Err(e) = archive.read_segment(off, kind, archive.footer_offset)
        {
            report.problems.push(format!("{name}: {e}"));
        }
    }

    // 2. Packs and chunks, in parallel.
    let mut chunks_by_pack: Vec<Vec<u32>> = vec![Vec::new(); index.packs.len()];
    for c in 0..index.chunks.len() as u32 {
        chunks_by_pack[index.chunks.pack[c as usize] as usize].push(c);
    }
    let pack_total: u64 = index.packs.iter().map(|p| p.ulen).sum();
    let file_total: u64 = index.snapshots.iter().flat_map(|s| &s.entries).map(|e| e.size).sum();
    let total = pack_total + file_total;

    let bad_chunks = Mutex::new(HashSet::new());
    let bad_packs = Mutex::new(Vec::new());
    let next = AtomicUsize::new(0);
    let cancelled = std::sync::atomic::AtomicBool::new(false);
    let threads = std::thread::available_parallelism().map_or(4, |n| n.get());
    let (tx, rx) = mpsc::channel::<u64>();
    std::thread::scope(|s| {
        for _ in 0..threads {
            let tx = tx.clone();
            let (next, bad_chunks, bad_packs, chunks_by_pack, cancelled) =
                (&next, &bad_chunks, &bad_packs, &chunks_by_pack, &cancelled);
            s.spawn(move || {
                loop {
                    let i = next.fetch_add(1, Ordering::Relaxed);
                    if i >= chunks_by_pack.len() || cancelled.load(Ordering::Relaxed) {
                        break;
                    }
                    match reader.decode_pack(i as u32) {
                        Ok(data) => {
                            for &c in &chunks_by_pack[i] {
                                let ch = index.chunks.get(c);
                                let slice = &data[ch.off as usize..(ch.off + ch.len) as usize];
                                if archive.chunk_id(slice) != ch.id {
                                    bad_chunks.lock().unwrap().insert(c);
                                }
                            }
                        }
                        Err(e) => bad_packs.lock().unwrap().push((i as u32, e.to_string())),
                    }
                    let _ = tx.send(index.packs[i].ulen);
                }
            });
        }
        drop(tx);
        let mut done = 0;
        for n in rx {
            done += n;
            if !progress(done, total) {
                cancelled.store(true, Ordering::Relaxed);
            }
        }
    });
    if cancelled.load(Ordering::Relaxed) {
        return Err(Error::Cancelled);
    }
    let mut bad_packs = bad_packs.into_inner().unwrap();
    bad_packs.sort();
    for (i, e) in &bad_packs {
        report.problems.push(format!("pack {i}: {e}"));
    }
    let bad_pack_set: HashSet<u32> = bad_packs.iter().map(|(i, _)| *i).collect();
    report.damaged_packs = bad_packs.into_iter().map(|(i, _)| i).collect();
    let bad_chunks = bad_chunks.into_inner().unwrap();
    if !bad_chunks.is_empty() {
        report.problems.push(format!("{} chunks do not match their IDs", bad_chunks.len()));
    }

    // 3. Files of every snapshot.
    let mut done = pack_total;
    for snap in &index.snapshots {
        let files: HashSet<&[u8]> =
            snap.entries.iter().filter(|e| e.kind == EntryKind::File).map(|e| e.path.as_slice()).collect();
        let mut entries: Vec<_> = snap.entries.iter().collect();
        entries.sort_by_key(|e| reader.first_location(e));
        for e in entries {
            let damage = reader.chunks_of(e).find_map(|c| {
                let pack = index.chunks.pack[c as usize];
                if bad_pack_set.contains(&pack) {
                    Some(format!("data in damaged pack {pack}"))
                } else if bad_chunks.contains(&c) {
                    Some(format!("damaged chunk {c}"))
                } else {
                    None
                }
            });
            let result = match (damage, e.kind) {
                (Some(reason), _) => Err(reason),
                (None, EntryKind::File) => reader.write_file(e, &mut Discard).map_err(|err| err.to_string()),
                (None, EntryKind::Hardlink) if !files.contains(e.target.as_deref().unwrap_or_default()) => {
                    Err("hardlink to a missing original".to_string())
                }
                _ => Ok(()),
            };
            match result {
                Ok(()) if e.kind == EntryKind::File => {
                    report.files += 1;
                    report.bytes += e.size;
                }
                Ok(()) => {}
                Err(reason) => {
                    report.damaged_files.push(DamagedFile { snapshot: snap.id, path: e.path_nfc.clone(), reason })
                }
            }
            done += e.size;
            if !progress(done, total) {
                return Err(Error::Cancelled);
            }
        }
    }
    Ok(report)
}
