//! File header (SPEC A5.1), 64 bytes at offset 0.

use crate::consts::{FORMAT_MAJOR, HEADER_LEN, HEADER_MAGIC};
use crate::error::{Error, Result, corrupt};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    pub major: u16,
    pub minor: u16,
    /// State at creation only; the last footer is authoritative (D-007).
    pub flags: u32,
    pub uuid: [u8; 16],
    pub created_ns: i64,
}

impl Header {
    pub fn new(flags: u32, uuid: [u8; 16], created_ns: i64) -> Self {
        Header { major: FORMAT_MAJOR, minor: crate::consts::FORMAT_MINOR, flags, uuid, created_ns }
    }

    pub fn encode(&self) -> [u8; HEADER_LEN] {
        let mut b = [0u8; HEADER_LEN];
        b[0..8].copy_from_slice(&HEADER_MAGIC);
        b[8..10].copy_from_slice(&self.major.to_le_bytes());
        b[10..12].copy_from_slice(&self.minor.to_le_bytes());
        b[12..16].copy_from_slice(&self.flags.to_le_bytes());
        b[16..32].copy_from_slice(&self.uuid);
        b[32..40].copy_from_slice(&self.created_ns.to_le_bytes());
        let crc = crc32c::crc32c(&b[..60]);
        b[60..64].copy_from_slice(&crc.to_le_bytes());
        b
    }

    /// Checks magic, checksum and version.
    pub fn decode(b: &[u8]) -> Result<Header> {
        if b.len() < HEADER_LEN || b[0..8] != HEADER_MAGIC {
            return Err(Error::NotArchydes);
        }
        let crc = u32::from_le_bytes(b[60..64].try_into().unwrap());
        if crc != crc32c::crc32c(&b[..60]) {
            return Err(corrupt("header checksum"));
        }
        let header = Header {
            major: u16::from_le_bytes(b[8..10].try_into().unwrap()),
            minor: u16::from_le_bytes(b[10..12].try_into().unwrap()),
            flags: u32::from_le_bytes(b[12..16].try_into().unwrap()),
            uuid: b[16..32].try_into().unwrap(),
            created_ns: i64::from_le_bytes(b[32..40].try_into().unwrap()),
        };
        if header.major != FORMAT_MAJOR {
            return Err(Error::UnsupportedVersion(header.major, header.minor));
        }
        Ok(header)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let h = Header::new(0, [7; 16], -5);
        assert_eq!(Header::decode(&h.encode()).unwrap(), h);
    }

    #[test]
    fn rejects_damage_and_newer_major() {
        let h = Header::new(0, [7; 16], 1);
        let mut b = h.encode();
        b[20] ^= 1;
        assert!(matches!(Header::decode(&b), Err(Error::Corrupt(_))));

        let mut newer = h;
        newer.major = 2;
        assert!(matches!(Header::decode(&newer.encode()), Err(Error::UnsupportedVersion(2, _))));
        assert!(matches!(Header::decode(b"PK\x03\x04"), Err(Error::NotArchydes)));
    }
}
