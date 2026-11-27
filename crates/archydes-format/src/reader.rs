//! Opening an archive (SPEC A5.4): header → footer → INDEX, falling back to INDEX_COPY and,
//! if the footer is damaged, to a backward search for the last valid footer or index.

use std::fs::File;
use std::io;

use crate::consts::{
    FOOTER_LEN, FOOTER_MAGIC, FORMAT_MINOR_ENCRYPTED, HEADER_LEN, SEGMENT_HEADER_LEN, SEGMENT_MAGIC, flags,
    segment_type,
};
use crate::crypto::{Encryption, KeyInfo, Keys, segment_class};
use crate::error::{Error, Result, corrupt};
use crate::footer::Footer;
use crate::header::Header;
use crate::index::{Index, PackRef};
use crate::pack::PackHeader;
use crate::segment::SegmentHeader;

/// Positional reads, so several threads can read one archive.
pub trait ReadAt: Send + Sync {
    fn read_exact_at(&self, buf: &mut [u8], offset: u64) -> io::Result<()>;
    fn size(&self) -> io::Result<u64>;
}

impl<T: ReadAt + ?Sized> ReadAt for &T {
    fn read_exact_at(&self, buf: &mut [u8], offset: u64) -> io::Result<()> {
        (**self).read_exact_at(buf, offset)
    }

    fn size(&self) -> io::Result<u64> {
        (**self).size()
    }
}

impl ReadAt for File {
    #[cfg(unix)]
    fn read_exact_at(&self, buf: &mut [u8], offset: u64) -> io::Result<()> {
        std::os::unix::fs::FileExt::read_exact_at(self, buf, offset)
    }

    #[cfg(windows)]
    fn read_exact_at(&self, mut buf: &mut [u8], mut offset: u64) -> io::Result<()> {
        use std::os::windows::fs::FileExt;
        while !buf.is_empty() {
            match self.seek_read(buf, offset)? {
                0 => return Err(io::ErrorKind::UnexpectedEof.into()),
                n => {
                    buf = &mut buf[n..];
                    offset += n as u64;
                }
            }
        }
        Ok(())
    }

    fn size(&self) -> io::Result<u64> {
        Ok(self.metadata()?.len())
    }
}

impl ReadAt for [u8] {
    fn read_exact_at(&self, buf: &mut [u8], offset: u64) -> io::Result<()> {
        let start = usize::try_from(offset).map_err(|_| io::ErrorKind::UnexpectedEof)?;
        let end = start.checked_add(buf.len()).ok_or(io::ErrorKind::UnexpectedEof)?;
        let src = self.get(start..end).ok_or(io::ErrorKind::UnexpectedEof)?;
        buf.copy_from_slice(src);
        Ok(())
    }

    fn size(&self) -> io::Result<u64> {
        Ok(self.len() as u64)
    }
}

impl ReadAt for Vec<u8> {
    fn read_exact_at(&self, buf: &mut [u8], offset: u64) -> io::Result<()> {
        self.as_slice().read_exact_at(buf, offset)
    }

    fn size(&self) -> io::Result<u64> {
        Ok(self.len() as u64)
    }
}

/// An opened archive: checked header, footer and index.
pub struct Archive<R: ReadAt> {
    src: R,
    size: u64,
    pub header: Header,
    pub footer: Footer,
    /// Where the footer in use starts.
    pub footer_offset: u64,
    pub index: Index,
    /// Problems that were worked around while opening (damaged footer, damaged index …).
    pub warnings: Vec<String>,
    /// Bytes after the footer in use that are the remains of an interrupted append (SPEC A10):
    /// not part of the archive, removed by the next append. 0 = none.
    pub interrupted: u64,
    /// Encrypted archives: the unlocked keys and the KEY_INFO payload they came from.
    keys: Option<(Keys, Vec<u8>)>,
}

impl<R: ReadAt> Archive<R> {
    /// Opens an unencrypted archive; an encrypted one fails with [`Error::PasswordRequired`].
    pub fn open(src: R) -> Result<Self> {
        Self::open_with(src, None)
    }

    /// Opens an archive; `password` is used only if it is encrypted (SPEC A11).
    pub fn open_with(src: R, password: Option<&str>) -> Result<Self> {
        Self::open_inner(src, password.map(Unlock::Password))
    }

    /// Opens an encrypted archive with keys that were unlocked before (no Argon2). Wrong keys
    /// show up as an index that fails its authentication tag.
    pub fn open_with_keys(src: R, keys: Keys) -> Result<Self> {
        Self::open_inner(src, Some(Unlock::Keys(keys)))
    }

    /// The keys of an opened encrypted archive, for [`Archive::open_with_keys`].
    pub fn keys(&self) -> Option<&Keys> {
        self.keys.as_ref().map(|(k, _)| k)
    }

    /// Header checked, nothing else read yet.
    fn skeleton(src: R) -> Result<Self> {
        let size = src.size()?;
        if size < HEADER_LEN as u64 {
            return Err(Error::NotArchydes);
        }
        let mut hb = [0u8; HEADER_LEN];
        src.read_exact_at(&mut hb, 0)?;
        let header = Header::decode(&hb)?;
        let encrypted = header.flags & flags::ENCRYPTED != 0;
        if encrypted && header.minor < FORMAT_MINOR_ENCRYPTED {
            return Err(corrupt("encrypted archive with format 1.0"));
        }

        Ok(Archive {
            src,
            size,
            header,
            footer: Footer {
                major: 0,
                minor: 0,
                flags: 0,
                index_offset: 0,
                index_copy_offset: 0,
                recovery_offset: 0,
                generation: 0,
                key_info_offset: 0,
            },
            footer_offset: 0,
            index: Index {
                version: 0,
                generation: 0,
                created_ns: 0,
                cdc: None,
                packs: vec![],
                chunks: Default::default(),
                snapshots: vec![],
            },
            warnings: Vec::new(),
            interrupted: 0,
            keys: None,
        })
    }

    /// The KEY_INFO payload of an encrypted archive, found as when opening but without
    /// deriving anything; `None` for an unencrypted archive. With the header UUID it identifies
    /// the data key, e.g. for a cache of unlocked keys.
    pub fn key_info_of(src: R) -> Result<Option<(Header, Vec<u8>)>> {
        let archive = Self::skeleton(src)?;
        if archive.header.flags & flags::ENCRYPTED == 0 {
            return Ok(None);
        }
        let (_, payload) = archive.find_key_info()?;
        Ok(Some((archive.header, payload)))
    }

    fn open_inner(src: R, unlock: Option<Unlock<'_>>) -> Result<Self> {
        let mut archive = Self::skeleton(src)?;
        let (header, size) = (archive.header, archive.size);
        let encrypted = header.flags & flags::ENCRYPTED != 0;
        if encrypted {
            archive.keys = Some(archive.unlock(unlock.ok_or(Error::PasswordRequired)?)?);
        }

        let last = size.checked_sub(FOOTER_LEN as u64).filter(|&o| o >= HEADER_LEN as u64);
        let primary = match last {
            Some(off) => archive.footer_at(off).and_then(|f| archive.index_for(&f, off).map(|i| (f, off, i))),
            None => Err(corrupt("file too short for a footer")),
        };
        let (footer, footer_offset, index) = match primary {
            Ok(found) => found,
            Err(Error::UnsupportedVersion(a, b)) => return Err(Error::UnsupportedVersion(a, b)),
            Err(e) => {
                archive.warnings.push(format!("last footer unusable ({e}), searching backwards"));
                archive.search_backwards()?
            }
        };
        if (footer.flags ^ header.flags) & flags::ENCRYPTED != 0 {
            return Err(corrupt("header and footer disagree about encryption"));
        }
        if encrypted && footer.minor < FORMAT_MINOR_ENCRYPTED {
            return Err(corrupt("encrypted generation with format 1.0"));
        }
        if index.generation != footer.generation {
            archive.warnings.push("footer and index differ in generation".into());
        }
        archive.footer = footer;
        archive.footer_offset = footer_offset;
        archive.index = index;
        // Only the footer at the end was unusable and a valid footer was found: is the rest
        // an append that never got its footer?
        let end = footer_offset + FOOTER_LEN as u64;
        let only_tail_warning = archive.warnings.len() == 1 && archive.warnings[0].starts_with("last footer unusable");
        if only_tail_warning && end < size && footer.index_offset != 0 {
            match interrupted_tail(&archive.src, end, size) {
                Ok(()) => {
                    archive.warnings.clear();
                    archive.interrupted = size - end;
                }
                Err(why) => archive.warnings.push(why),
            }
        }
        Ok(archive)
    }

    pub fn is_encrypted(&self) -> bool {
        self.keys.is_some()
    }

    /// Keys, UUID and KEY_INFO for writing a new generation of an encrypted archive.
    pub fn encryption(&self) -> Option<Encryption> {
        self.keys.as_ref().map(|(keys, info)| Encryption {
            keys: keys.clone(),
            uuid: self.header.uuid,
            key_info: info.clone(),
        })
    }

    /// The ID of a chunk with this content: BLAKE3-256, or keyed BLAKE3 when encrypted (A11).
    pub fn chunk_id(&self, data: &[u8]) -> [u8; 32] {
        match &self.keys {
            Some((keys, _)) => keys.chunk_id(data),
            None => crate::hash256(data),
        }
    }

    /// Finds KEY_INFO (via the last footer, else the first readable one from the start, else
    /// searching backwards) and unlocks it. Argon2 runs once: all KEY_INFO segments are equal.
    fn unlock(&self, unlock: Unlock<'_>) -> Result<(Keys, Vec<u8>)> {
        let (info, payload) = self.find_key_info()?;
        match unlock {
            Unlock::Password(password) => Ok((info.unlock(password, &self.header.uuid)?, payload)),
            Unlock::Keys(keys) => Ok((keys, payload)),
        }
    }

    fn find_key_info(&self) -> Result<(KeyInfo, Vec<u8>)> {
        let mut candidates = Vec::new();
        if let Some(off) = self.size.checked_sub(FOOTER_LEN as u64)
            && let Ok(f) = self.footer_at(off)
            && f.key_info_offset != 0
        {
            candidates.push(f.key_info_offset);
        }
        candidates.extend(walk(&self.src).into_iter().find_map(|i| match i {
            WalkItem::Segment { offset, header } if header.kind == segment_type::KEY_INFO => Some(offset),
            _ => None,
        }));
        let mut last_error = corrupt("no readable KEY_INFO");
        let try_at = |off: u64| -> Result<(KeyInfo, Vec<u8>)> {
            let (_, payload) = self.read_segment(off, segment_type::KEY_INFO, self.size)?;
            Ok((KeyInfo::decode(&payload)?, payload))
        };
        let mut found = candidates.into_iter().find_map(|off| try_at(off).map_err(|e| last_error = e).ok());
        if found.is_none() {
            found = self.scan_backwards(|off| try_at(off).ok());
        }
        found.ok_or(last_error)
    }

    /// Calls `probe` at every segment magic from the end backwards until it returns something.
    fn scan_backwards<T>(&self, mut probe: impl FnMut(u64) -> Option<T>) -> Option<T> {
        const WINDOW: u64 = 1 << 20;
        let mut end = self.size;
        while end > HEADER_LEN as u64 {
            let start = end.saturating_sub(WINDOW).max(HEADER_LEN as u64);
            let read_end = (end + 3).min(self.size);
            let mut buf = vec![0u8; (read_end - start) as usize];
            self.src.read_exact_at(&mut buf, start).ok()?;
            for pos in (0..(end - start) as usize).rev() {
                if buf[pos..].starts_with(&SEGMENT_MAGIC)
                    && let Some(found) = probe(start + pos as u64)
                {
                    return Some(found);
                }
            }
            end = start;
        }
        None
    }

    pub fn source(&self) -> &R {
        &self.src
    }

    pub fn file_size(&self) -> u64 {
        self.size
    }

    fn footer_at(&self, off: u64) -> Result<Footer> {
        let mut b = [0u8; FOOTER_LEN];
        self.src.read_exact_at(&mut b, off)?;
        let footer = Footer::decode(&b)?;
        // A footer directly follows the last segment of its generation (SPEC A5.4). A copy
        // elsewhere, e.g. in the parity of a RECOVERY segment, is not a footer. A damaged
        // segment header does not reject the footer: repair may need it.
        let last = footer.index_offset.max(footer.index_copy_offset).max(footer.recovery_offset);
        let mut hb = [0u8; SEGMENT_HEADER_LEN];
        if last != 0
            && self.src.read_exact_at(&mut hb, last).is_ok()
            && let Ok(sh) = SegmentHeader::decode(&hb)
            && sh.end(last) != Some(off)
        {
            return Err(corrupt("footer does not follow the last segment of its generation"));
        }
        Ok(footer)
    }

    /// The index the footer at `footer_offset` points to, or its copy.
    fn index_for(&mut self, footer: &Footer, footer_offset: u64) -> Result<Index> {
        let check = |off: u64| off >= HEADER_LEN as u64 && off < footer_offset;
        let first = if check(footer.index_offset) {
            self.read_segment(footer.index_offset, segment_type::INDEX, footer_offset)
                .and_then(|(_, p)| Index::decode_payload(&p))
        } else {
            Err(corrupt("index offset outside the archive"))
        };
        match first {
            Ok(i) => Ok(i),
            Err(e) if footer.index_copy_offset != 0 && check(footer.index_copy_offset) => {
                let copy = self
                    .read_segment(footer.index_copy_offset, segment_type::INDEX_COPY, footer_offset)
                    .and_then(|(_, p)| Index::decode_payload(&p))?;
                self.warnings.push(format!("INDEX damaged ({e}), using INDEX_COPY"));
                Ok(copy)
            }
            Err(e) => Err(e),
        }
    }

    /// Reads a segment whose header is at `off`, checks type and payload hash, and decrypts
    /// it in an encrypted archive. The payload must end at or before `limit`.
    pub fn read_segment(&self, off: u64, expected_kind: u16, limit: u64) -> Result<(SegmentHeader, Vec<u8>)> {
        let (sh, mut payload) = self.read_segment_stored(off, expected_kind, limit)?;
        if let Some(class) = segment_class(sh.kind).filter(|_| sh.is_encrypted()) {
            let (keys, _) = self.keys.as_ref().ok_or(Error::PasswordRequired)?;
            payload = keys.open(&self.header.uuid, class, &payload).map_err(|_| {
                corrupt(format!("{} segment at {off}: authentication tag mismatch", segment_type::name(sh.kind)))
            })?;
        }
        Ok((sh, payload))
    }

    /// Like [`Archive::read_segment`], but returns the payload as stored (still encrypted), for
    /// copying a segment into a new file of the same archive.
    pub fn read_segment_stored(&self, off: u64, expected_kind: u16, limit: u64) -> Result<(SegmentHeader, Vec<u8>)> {
        let mut hb = [0u8; SEGMENT_HEADER_LEN];
        self.src.read_exact_at(&mut hb, off)?;
        let sh = SegmentHeader::decode(&hb)?;
        if sh.kind != expected_kind {
            return Err(corrupt(format!(
                "expected {} segment at {off}, found {}",
                segment_type::name(expected_kind),
                segment_type::name(sh.kind)
            )));
        }
        let class = segment_class(sh.kind).filter(|_| self.header.flags & flags::ENCRYPTED != 0);
        if sh.is_encrypted() != class.is_some() {
            return Err(corrupt(format!(
                "{} segment at {off} is {}encrypted",
                segment_type::name(sh.kind),
                if sh.is_encrypted() { "" } else { "not " }
            )));
        }
        match sh.end(off) {
            Some(end) if end <= limit.min(self.size) => {}
            _ => return Err(corrupt("segment extends beyond the archive")),
        }
        let mut payload = vec![0u8; sh.payload_len as usize];
        self.src.read_exact_at(&mut payload, off + SEGMENT_HEADER_LEN as u64)?;
        if crate::hash128(&payload) != sh.payload_hash {
            return Err(corrupt(format!("{} segment at {off}: hash mismatch", segment_type::name(sh.kind))));
        }
        Ok((sh, payload))
    }

    /// Reads pack `i`: checks the segment against the index and returns header and data.
    pub fn read_pack(&self, i: usize) -> Result<(PackHeader, Vec<u8>)> {
        let pr: PackRef = *self.index.packs.get(i).ok_or_else(|| corrupt("pack number"))?;
        let (sh, mut payload) = self.read_segment(pr.off, segment_type::PACK, self.footer_offset)?;
        if sh.payload_hash != pr.hash {
            return Err(corrupt(format!("pack {i}: segment differs from index")));
        }
        let (header, data) = PackHeader::decode_payload(&payload)?;
        if header.codec != pr.codec || header.ulen != pr.ulen || data.len() as u64 != pr.clen {
            return Err(corrupt(format!("pack {i}: header differs from index")));
        }
        let start = payload.len() - data.len();
        payload.drain(..start);
        Ok((header, payload))
    }

    /// Backward search: the last footer whose index is readable, else the last readable index.
    fn search_backwards(&mut self) -> Result<(Footer, u64, Index)> {
        const WINDOW: u64 = 1 << 20;
        let mut index_candidates = Vec::new();
        let mut end = self.size;
        while end > HEADER_LEN as u64 {
            let start = end.saturating_sub(WINDOW).max(HEADER_LEN as u64);
            // Overlap by the magic length so a magic across the boundary is found.
            let read_end = (end + 7).min(self.size);
            let mut buf = vec![0u8; (read_end - start) as usize];
            self.src.read_exact_at(&mut buf, start)?;
            for pos in (0..(end - start) as usize).rev() {
                let off = start + pos as u64;
                if buf[pos..].starts_with(&FOOTER_MAGIC)
                    && off + FOOTER_LEN as u64 <= self.size
                    && let Ok(f) = self.footer_at(off)
                    && let Ok(i) = self.index_for(&f, off)
                {
                    return Ok((f, off, i));
                }
                if buf[pos..].starts_with(&SEGMENT_MAGIC) {
                    index_candidates.push(off);
                }
            }
            end = start;
        }
        // No usable footer: take the last segment that is a readable index.
        for off in index_candidates {
            for kind in [segment_type::INDEX, segment_type::INDEX_COPY] {
                if let Ok((sh, p)) = self.read_segment(off, kind, self.size)
                    && let Ok(i) = Index::decode_payload(&p)
                {
                    self.warnings.push("no valid footer, using the last readable index".into());
                    let footer = Footer {
                        major: self.header.major,
                        minor: self.header.minor,
                        flags: self.header.flags,
                        // Only the segment actually found; the other one stays unknown.
                        index_offset: if kind == segment_type::INDEX { off } else { 0 },
                        index_copy_offset: if kind == segment_type::INDEX_COPY { off } else { 0 },
                        recovery_offset: 0,
                        generation: i.generation,
                        key_info_offset: 0,
                    };
                    let end = sh.end(off).unwrap_or(self.size);
                    return Ok((footer, end, i));
                }
            }
        }
        Err(corrupt("no readable index found"))
    }

    /// Walks all segments and footers from the start of the file (for `verify`), without the
    /// remains of an interrupted append.
    pub fn walk(&self) -> Vec<WalkItem> {
        let end = self.size - self.interrupted;
        let mut items = walk(&self.src);
        items.retain(|i| match i {
            WalkItem::Segment { offset, .. } | WalkItem::Footer { offset, .. } | WalkItem::Damaged { offset } => {
                *offset < end
            }
        });
        items
    }
}

enum Unlock<'a> {
    Password(&'a str),
    Keys(Keys),
}

/// Decides whether `[end, size)`, the bytes after the last valid footer, are the remains of an
/// append that was interrupted before its footer was written (SPEC A10, D-035). Such remains
/// hold only PACK, KEY_INFO (the copy of an encrypted generation, SPEC A11), INDEX, INDEX_COPY
/// and RECOVERY segments, the last one possibly incomplete, and no footer. Anything that could be a complete newer generation with a damaged footer is
/// rejected with the reason: `repair` may restore it.
pub fn interrupted_tail<R: ReadAt + ?Sized>(src: &R, end: u64, size: u64) -> std::result::Result<(), String> {
    let damaged_footer = "the newest footer is damaged".to_string();
    if size - end >= FOOTER_LEN as u64 {
        let mut magic = [0u8; 8];
        src.read_exact_at(&mut magic, size - FOOTER_LEN as u64).map_err(|e| e.to_string())?;
        if magic == FOOTER_MAGIC {
            return Err(damaged_footer);
        }
    }
    for item in walk_from(src, end) {
        match item {
            WalkItem::Segment { offset, header } => {
                if !matches!(
                    header.kind,
                    segment_type::PACK
                        | segment_type::KEY_INFO
                        | segment_type::INDEX
                        | segment_type::INDEX_COPY
                        | segment_type::RECOVERY
                ) {
                    return Err(format!("{} segment after the last footer", segment_type::name(header.kind)));
                }
                // INDEX_COPY or RECOVERY followed by exactly a footer's length: a complete
                // generation whose footer is unreadable.
                let seg_end = header.end(offset).unwrap_or(u64::MAX);
                if matches!(header.kind, segment_type::INDEX_COPY | segment_type::RECOVERY)
                    && seg_end.checked_add(FOOTER_LEN as u64) == Some(size)
                {
                    return Err(damaged_footer);
                }
            }
            WalkItem::Footer { .. } => return Err("a newer footer exists but its index is unreadable".into()),
            WalkItem::Damaged { .. } => {}
        }
    }
    Ok(())
}

/// Walks all segments and footers from the end of the header, without trusting anything but
/// the checksums of what it finds. Stops at the first place that is neither.
pub fn walk<R: ReadAt + ?Sized>(src: &R) -> Vec<WalkItem> {
    walk_from(src, HEADER_LEN as u64)
}

/// Like [`walk`], starting at `off` (which must be the start of a segment or footer).
pub fn walk_from<R: ReadAt + ?Sized>(src: &R, mut off: u64) -> Vec<WalkItem> {
    let size = src.size().unwrap_or(0);
    let mut items = Vec::new();
    while off < size {
        let mut probe = [0u8; 8];
        let n = (size - off).min(8) as usize;
        if src.read_exact_at(&mut probe[..n], off).is_err() {
            items.push(WalkItem::Damaged { offset: off });
            break;
        }
        if probe[..n] == FOOTER_MAGIC[..n] && n == 8 {
            let mut b = [0u8; FOOTER_LEN];
            match src.read_exact_at(&mut b, off).map_err(Error::from).and_then(|_| Footer::decode(&b)) {
                Ok(f) => items.push(WalkItem::Footer { offset: off, footer: f }),
                Err(_) => {
                    items.push(WalkItem::Damaged { offset: off });
                    break;
                }
            }
            off += FOOTER_LEN as u64;
            continue;
        }
        let mut hb = [0u8; SEGMENT_HEADER_LEN];
        let header = src.read_exact_at(&mut hb, off).ok().and_then(|_| SegmentHeader::decode(&hb).ok());
        match header.and_then(|h| h.end(off).filter(|&e| e <= size).map(|e| (h, e))) {
            Some((h, end)) => {
                items.push(WalkItem::Segment { offset: off, header: h });
                off = end;
            }
            None => {
                items.push(WalkItem::Damaged { offset: off });
                break;
            }
        }
    }
    items
}

#[derive(Debug, Clone, Copy)]
pub enum WalkItem {
    Segment {
        offset: u64,
        header: SegmentHeader,
    },
    Footer {
        offset: u64,
        footer: Footer,
    },
    /// Neither a segment nor a footer starts here; walking stops.
    Damaged {
        offset: u64,
    },
}
