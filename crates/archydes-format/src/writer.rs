//! Writing the container structures (D-005a). Decides nothing about content: the caller hands
//! over finished packs and the finished index.

use std::io::{Seek, SeekFrom, Write};

use crate::consts::{
    FORMAT_MAJOR, FORMAT_MINOR, FORMAT_MINOR_ENCRYPTED, SEGMENT_HEADER_LEN, flags, segment_flags, segment_type,
};
use crate::crypto::{Encryption, segment_class};
use crate::error::{Result, corrupt};
use crate::footer::Footer;
use crate::header::Header;
use crate::index::{Index, PackRef};
use crate::pack::PackHeader;
use crate::segment::SegmentHeader;

pub fn format_info_text() -> String {
    format_info_text_for(FORMAT_MINOR)
}

/// FORMAT_INFO for format 1.`minor`; encrypted archives say so, since nothing else is readable.
pub fn format_info_text_for(minor: u16) -> String {
    let encrypted = if minor >= FORMAT_MINOR_ENCRYPTED { " Encrypted: a password is needed to read it." } else { "" };
    format!(
        "Archydes archive, format {FORMAT_MAJOR}.{minor}.{encrypted}\n\
         Specification: https://archydes.app/format (CC BY 4.0).\n\
         Free tool to list, extract, verify and repair: archydes (MIT OR Apache-2.0).\n"
    )
}

pub struct ArchiveWriter<W: Write> {
    out: W,
    offset: u64,
    encryption: Option<Encryption>,
    /// The KEY_INFO this generation points to (encrypted archives).
    key_info_offset: u64,
}

impl<W: Write> ArchiveWriter<W> {
    /// Writes the header and the FORMAT_INFO segment.
    pub fn new(out: W, header: &Header) -> Result<Self> {
        if header.flags & flags::ENCRYPTED != 0 {
            return Err(corrupt("an encrypted archive needs ArchiveWriter::new_encrypted"));
        }
        Self::start(out, header, None)
    }

    /// Writes the header (format 1.1, encrypted), FORMAT_INFO and KEY_INFO (SPEC A11).
    pub fn new_encrypted(out: W, header: &Header, encryption: Encryption) -> Result<Self> {
        if header.flags & flags::ENCRYPTED == 0
            || header.minor < FORMAT_MINOR_ENCRYPTED
            || header.uuid != encryption.uuid
        {
            return Err(corrupt("header does not match the encryption"));
        }
        Self::start(out, header, Some(encryption))
    }

    fn start(mut out: W, header: &Header, encryption: Option<Encryption>) -> Result<Self> {
        out.write_all(&header.encode())?;
        let mut w =
            ArchiveWriter { out, offset: crate::consts::HEADER_LEN as u64, encryption: None, key_info_offset: 0 };
        w.write_segment(segment_type::FORMAT_INFO, 0, &[format_info_text_for(header.minor).as_bytes()])?;
        if let Some(e) = encryption {
            w.write_segment(segment_type::KEY_INFO, segment_flags::CRITICAL, &[&e.key_info])?;
            w.encryption = Some(e);
        }
        Ok(w)
    }

    /// Continues an existing archive for a new generation (SPEC A10): `out` is positioned at
    /// `offset`, the end of the last footer. Nothing before it is ever written again.
    pub fn append(out: W, offset: u64) -> Self {
        ArchiveWriter { out, offset, encryption: None, key_info_offset: 0 }
    }

    /// Continues an encrypted archive: like [`ArchiveWriter::append`], with its keys.
    pub fn append_encrypted(out: W, offset: u64, encryption: Encryption) -> Self {
        ArchiveWriter { out, offset, encryption: Some(encryption), key_info_offset: 0 }
    }

    pub fn offset(&self) -> u64 {
        self.offset
    }

    pub fn encryption(&self) -> Option<&Encryption> {
        self.encryption.as_ref()
    }

    /// Format minor version and the footer's `key_info_offset` for what this writer wrote.
    pub fn minor(&self) -> u16 {
        if self.encryption.is_some() { FORMAT_MINOR_ENCRYPTED } else { FORMAT_MINOR }
    }

    pub fn key_info_offset(&self) -> u64 {
        self.key_info_offset
    }

    /// Seals `parts` when the archive is encrypted and the segment type is one that is.
    fn sealed(&self, kind: u16, flags: u16, parts: &[&[u8]]) -> Result<Option<(u16, Vec<u8>)>> {
        match (&self.encryption, segment_class(kind)) {
            (Some(e), Some(class)) => {
                let plain = parts.concat();
                Ok(Some((flags | segment_flags::ENCRYPTED, e.keys.seal(&e.uuid, class, &plain)?)))
            }
            _ => Ok(None),
        }
    }

    /// Writes one segment; in an encrypted archive PACK, INDEX and INDEX_COPY are sealed first.
    pub fn write_payload(&mut self, kind: u16, flags: u16, parts: &[&[u8]]) -> Result<(u64, SegmentHeader)> {
        match self.sealed(kind, flags, parts)? {
            Some((flags, sealed)) => self.write_segment(kind, flags, &[&sealed]),
            None => self.write_segment(kind, flags, parts),
        }
    }

    /// Writes one segment whose payload is the concatenation of `parts`; returns its offset
    /// and header.
    pub fn write_segment(&mut self, kind: u16, flags: u16, parts: &[&[u8]]) -> Result<(u64, SegmentHeader)> {
        let mut hasher = blake3::Hasher::new();
        let mut len = 0u64;
        for p in parts {
            hasher.update(p);
            len += p.len() as u64;
        }
        let mut hash = [0u8; 16];
        hash.copy_from_slice(&hasher.finalize().as_bytes()[..16]);
        let sh = SegmentHeader { kind, flags, payload_len: len, payload_hash: hash };
        let off = self.offset;
        self.out.write_all(&sh.encode())?;
        for p in parts {
            self.out.write_all(p)?;
        }
        self.offset += SEGMENT_HEADER_LEN as u64 + len;
        Ok((off, sh))
    }

    pub fn write_pack(&mut self, header: &PackHeader, data: &[u8]) -> Result<PackRef> {
        let prefix = header.encode_prefix();
        let (off, sh) = self.write_payload(segment_type::PACK, segment_flags::CRITICAL, &[&prefix, data])?;
        Ok(PackRef { off, clen: data.len() as u64, ulen: header.ulen, codec: header.codec, hash: sh.payload_hash })
    }

    /// Writes a pack sealed beforehand with [`Encryption::seal_pack`] (e.g. on another thread);
    /// `clen` is the length of the compressed data before sealing.
    pub fn write_sealed_pack(&mut self, header: &PackHeader, clen: u64, sealed: &[u8]) -> Result<PackRef> {
        if self.encryption.is_none() {
            return Err(corrupt("a sealed pack in an unencrypted archive"));
        }
        let flags = segment_flags::CRITICAL | segment_flags::ENCRYPTED;
        let (off, sh) = self.write_segment(segment_type::PACK, flags, &[sealed])?;
        Ok(PackRef { off, clen, ulen: header.ulen, codec: header.codec, hash: sh.payload_hash })
    }

    /// Direct access to the output, e.g. to flush it before reading back what was written.
    pub fn get_mut(&mut self) -> &mut W {
        &mut self.out
    }

    /// Writes INDEX and INDEX_COPY; returns their offsets. In an encrypted archive a copy of
    /// KEY_INFO comes first (D-054), and both index segments hold the same ciphertext.
    pub fn write_index(&mut self, index: &Index) -> Result<(u64, u64)> {
        let mut payload = index.encode_payload();
        let mut flags = 0;
        if let Some(e) = &self.encryption {
            let key_info = e.key_info.clone();
            payload = e.keys.seal(&e.uuid, segment_class(segment_type::INDEX).unwrap_or(2), &payload)?;
            flags = segment_flags::ENCRYPTED;
            (self.key_info_offset, _) =
                self.write_segment(segment_type::KEY_INFO, segment_flags::CRITICAL, &[&key_info])?;
        }
        let (index_offset, _) =
            self.write_segment(segment_type::INDEX, segment_flags::CRITICAL | flags, &[&payload])?;
        let (index_copy_offset, _) = self.write_segment(segment_type::INDEX_COPY, flags, &[&payload])?;
        Ok((index_offset, index_copy_offset))
    }

    /// Writes the footer and flushes. The caller syncs the returned writer; only then is the
    /// generation valid.
    pub fn write_footer(mut self, footer: &Footer) -> Result<W> {
        self.out.write_all(&footer.encode())?;
        self.out.flush()?;
        Ok(self.out)
    }

    /// Writes INDEX, INDEX_COPY and the footer, without recovery data.
    pub fn finish(mut self, index: &Index, flags: u32) -> Result<W> {
        let (index_offset, index_copy_offset) = self.write_index(index)?;
        let encrypted = if self.encryption.is_some() { flags::ENCRYPTED } else { 0 };
        let footer = Footer {
            major: FORMAT_MAJOR,
            minor: self.minor(),
            flags: flags | encrypted,
            index_offset,
            index_copy_offset,
            recovery_offset: 0,
            generation: index.generation,
            key_info_offset: self.key_info_offset,
        };
        self.write_footer(&footer)
    }
}

impl<W: Write + Seek> ArchiveWriter<W> {
    /// Writes a segment whose payload of exactly `len` bytes is produced by `fill`, without
    /// holding it in memory. See [`write_segment_streamed`].
    pub fn write_segment_with(
        &mut self,
        kind: u16,
        flags: u16,
        len: u64,
        fill: impl FnOnce(&mut dyn Write) -> Result<()>,
    ) -> Result<(u64, SegmentHeader)> {
        if self.encryption.is_some() && segment_class(kind).is_some() {
            return Err(corrupt("encrypted segments cannot be streamed"));
        }
        let off = self.offset;
        let sh = write_segment_streamed(&mut self.out, off, kind, flags, len, fill)?;
        self.offset += SEGMENT_HEADER_LEN as u64 + len;
        Ok((off, sh))
    }
}

/// Writes a segment at `off` (the current position of `out`): a placeholder header, the payload
/// from `fill`, then the real header with the payload hash. Leaves `out` positioned after the
/// payload. Fails if `fill` writes more or less than `len` bytes.
pub fn write_segment_streamed<W: Write + Seek>(
    out: &mut W,
    off: u64,
    kind: u16,
    flags: u16,
    len: u64,
    fill: impl FnOnce(&mut dyn Write) -> Result<()>,
) -> Result<SegmentHeader> {
    out.write_all(&[0u8; SEGMENT_HEADER_LEN])?;
    let mut hw = HashingWriter { out: &mut *out, hasher: blake3::Hasher::new(), len: 0 };
    fill(&mut hw)?;
    let (hasher, written) = (hw.hasher, hw.len);
    if written != len {
        return Err(crate::corrupt(format!("segment payload is {written} bytes, announced {len}")));
    }
    let mut hash = [0u8; 16];
    hash.copy_from_slice(&hasher.finalize().as_bytes()[..16]);
    let sh = SegmentHeader { kind, flags, payload_len: len, payload_hash: hash };
    out.seek(SeekFrom::Start(off))?;
    out.write_all(&sh.encode())?;
    out.seek(SeekFrom::Start(off + SEGMENT_HEADER_LEN as u64 + len))?;
    Ok(sh)
}

struct HashingWriter<'a, W: Write> {
    out: &'a mut W,
    hasher: blake3::Hasher,
    len: u64,
}

impl<W: Write> Write for HashingWriter<'_, W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let n = self.out.write(buf)?;
        self.hasher.update(&buf[..n]);
        self.len += n as u64;
        Ok(n)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.out.flush()
    }
}
