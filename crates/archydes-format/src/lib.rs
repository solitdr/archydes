//! Container structures of the Archydes archive format (`.archy`).
//!
//! This crate reads and writes the fixed structures defined in `SPEC.md`: header, segment
//! headers, footer, pack headers and the index. It knows nothing about how a packer decides
//! what goes where; it only guarantees that what it writes is a valid archive and that what it
//! reads is checked (checksums, hashes, limits) before anyone uses it.
//!
//! All input is treated as untrusted.

pub mod cbor;
pub mod consts;
pub mod crypto;
pub mod error;
pub mod footer;
pub mod header;
pub mod index;
pub mod pack;
pub mod reader;
pub mod segment;
pub mod writer;

pub use crypto::{Encryption, KdfParams, KeyInfo, Keys};
pub use error::{Error, Result, corrupt};
pub use footer::Footer;
pub use header::Header;
pub use index::{ChunkTable, Entry, EntryKind, Index, PackRef, Part, Recipe, Snapshot, Stream};
pub use pack::PackHeader;
pub use reader::{Archive, ReadAt, WalkItem, interrupted_tail, walk, walk_from};
pub use segment::SegmentHeader;
pub use writer::{ArchiveWriter, write_segment_streamed};

/// BLAKE3-128: the first 16 bytes of BLAKE3, used for segment payloads.
pub fn hash128(data: &[u8]) -> [u8; 16] {
    let h = blake3::hash(data);
    let mut out = [0u8; 16];
    out.copy_from_slice(&h.as_bytes()[..16]);
    out
}

/// BLAKE3-256, used for chunk IDs and file hashes.
pub fn hash256(data: &[u8]) -> [u8; 32] {
    *blake3::hash(data).as_bytes()
}
