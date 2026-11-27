//! Magic numbers, registries and limits from the specification.

/// `\x89ARCH\r\n\x1A`
pub const HEADER_MAGIC: [u8; 8] = *b"\x89ARCH\r\n\x1a";
pub const SEGMENT_MAGIC: [u8; 4] = *b"AHSG";
pub const FOOTER_MAGIC: [u8; 8] = *b"AHYEND\0\0";

pub const HEADER_LEN: usize = 64;
pub const SEGMENT_HEADER_LEN: usize = 40;
pub const FOOTER_LEN: usize = 64;

pub const FORMAT_MAJOR: u16 = 1;
pub const FORMAT_MINOR: u16 = 0;
/// Encrypted archives (SPEC A11); unencrypted ones stay 1.0.
pub const FORMAT_MINOR_ENCRYPTED: u16 = 1;

/// Archive flags (header and footer).
pub mod flags {
    pub const ENCRYPTED: u32 = 1 << 0;
    pub const RECOVERY: u32 = 1 << 1;
    pub const MULTIPLE_SNAPSHOTS: u32 = 1 << 2;
}

/// Segment flags.
pub mod segment_flags {
    pub const CRITICAL: u16 = 1 << 0;
    pub const ENCRYPTED: u16 = 1 << 1;
}

/// Segment types.
pub mod segment_type {
    pub const PACK: u16 = 0x0001;
    pub const INDEX: u16 = 0x0002;
    pub const INDEX_COPY: u16 = 0x0003;
    pub const RECOVERY: u16 = 0x0004;
    pub const FORMAT_INFO: u16 = 0x0005;
    pub const PLAIN_TOC: u16 = 0x0006;
    pub const KEY_INFO: u16 = 0x0007;

    pub fn name(kind: u16) -> &'static str {
        match kind {
            PACK => "PACK",
            INDEX => "INDEX",
            INDEX_COPY => "INDEX_COPY",
            RECOVERY => "RECOVERY",
            FORMAT_INFO => "FORMAT_INFO",
            PLAIN_TOC => "PLAIN_TOC",
            KEY_INFO => "KEY_INFO",
            0x8000..=0xFFFF => "experimental",
            _ => "unknown",
        }
    }

    /// Types this version knows (the rest is skipped unless critical).
    pub fn is_known(kind: u16) -> bool {
        matches!(kind, PACK..=KEY_INFO)
    }
}

/// Codec registry (SPEC A5.3).
pub mod codec {
    pub const NONE: u64 = 0;
    pub const ZSTD: u64 = 1;
    pub const LZMA2: u64 = 2;

    pub fn name(id: u64) -> &'static str {
        match id {
            NONE => "none",
            ZSTD => "zstd",
            LZMA2 => "LZMA2",
            _ => "unknown",
        }
    }
}

/// Transformation registry (SPEC A7).
pub mod transform {
    pub const RAW: u64 = 0;
    pub const ZLIB_EXACT: u64 = 1;
    pub const PREFLATE: u64 = 2;
    pub const JPEG_FROM_JXL: u64 = 3;

    pub fn name(id: u64) -> &'static str {
        match id {
            RAW => "RAW",
            ZLIB_EXACT => "ZLIB_EXACT",
            PREFLATE => "PREFLATE",
            JPEG_FROM_JXL => "JPEG_FROM_JXL",
            _ => "unknown",
        }
    }
}

/// Codec byte in front of the index payload.
pub mod index_codec {
    pub const ZSTD: u8 = 1;
}

/// Limits a decoder enforces against hostile input (SPEC A12).
pub mod limits {
    /// Largest uncompressed index.
    pub const MAX_INDEX_ULEN: u64 = 1 << 30;
    /// Largest uncompressed pack (SPEC A5.3).
    pub const MAX_PACK_ULEN: u64 = 64 << 20;
    /// Largest CBOR pack header.
    pub const MAX_PACK_HEADER_LEN: u32 = 4096;
    /// Largest LZMA2 dictionary a decoder accepts.
    pub const MAX_LZMA2_DICT: u64 = 256 << 20;
    /// Nesting depth for CBOR.
    pub const MAX_CBOR_DEPTH: usize = 32;
}
