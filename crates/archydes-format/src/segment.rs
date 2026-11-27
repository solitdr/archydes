//! Segment header (SPEC A5.2), 40 bytes in front of every segment payload.

use crate::consts::{SEGMENT_HEADER_LEN, SEGMENT_MAGIC, segment_flags};
use crate::error::{Result, corrupt};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SegmentHeader {
    pub kind: u16,
    pub flags: u16,
    pub payload_len: u64,
    /// BLAKE3-128 of the payload as stored.
    pub payload_hash: [u8; 16],
}

impl SegmentHeader {
    pub fn encode(&self) -> [u8; SEGMENT_HEADER_LEN] {
        let mut b = [0u8; SEGMENT_HEADER_LEN];
        b[0..4].copy_from_slice(&SEGMENT_MAGIC);
        b[4..6].copy_from_slice(&self.kind.to_le_bytes());
        b[6..8].copy_from_slice(&self.flags.to_le_bytes());
        b[8..16].copy_from_slice(&self.payload_len.to_le_bytes());
        b[16..32].copy_from_slice(&self.payload_hash);
        let crc = crc32c::crc32c(&b[..36]);
        b[36..40].copy_from_slice(&crc.to_le_bytes());
        b
    }

    pub fn decode(b: &[u8]) -> Result<SegmentHeader> {
        if b.len() < SEGMENT_HEADER_LEN || b[0..4] != SEGMENT_MAGIC {
            return Err(corrupt("segment magic missing"));
        }
        let crc = u32::from_le_bytes(b[36..40].try_into().unwrap());
        if crc != crc32c::crc32c(&b[..36]) {
            return Err(corrupt("segment header checksum"));
        }
        Ok(SegmentHeader {
            kind: u16::from_le_bytes(b[4..6].try_into().unwrap()),
            flags: u16::from_le_bytes(b[6..8].try_into().unwrap()),
            payload_len: u64::from_le_bytes(b[8..16].try_into().unwrap()),
            payload_hash: b[16..32].try_into().unwrap(),
        })
    }

    pub fn is_critical(&self) -> bool {
        self.flags & segment_flags::CRITICAL != 0
    }

    pub fn is_encrypted(&self) -> bool {
        self.flags & segment_flags::ENCRYPTED != 0
    }

    /// Offset just past the payload, for a header at `offset`.
    pub fn end(&self, offset: u64) -> Option<u64> {
        offset.checked_add(SEGMENT_HEADER_LEN as u64)?.checked_add(self.payload_len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_and_checksum() {
        let s = SegmentHeader { kind: 1, flags: 1, payload_len: 99, payload_hash: [3; 16] };
        let mut b = s.encode();
        assert_eq!(SegmentHeader::decode(&b).unwrap(), s);
        b[9] ^= 0x40;
        assert!(SegmentHeader::decode(&b).is_err());
    }
}
