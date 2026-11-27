//! Footer (SPEC A5.4), the last 64 bytes of a generation.

use crate::consts::{FOOTER_LEN, FOOTER_MAGIC, FORMAT_MAJOR};
use crate::error::{Error, Result, corrupt};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Footer {
    pub major: u16,
    pub minor: u16,
    /// Authoritative flags of this generation (D-007).
    pub flags: u32,
    pub index_offset: u64,
    pub index_copy_offset: u64,
    /// 0 = no recovery data.
    pub recovery_offset: u64,
    pub generation: u64,
    /// Encrypted archives: the KEY_INFO copy of this generation (D-054); otherwise 0.
    pub key_info_offset: u64,
}

impl Footer {
    pub fn encode(&self) -> [u8; FOOTER_LEN] {
        let mut b = [0u8; FOOTER_LEN];
        b[0..8].copy_from_slice(&FOOTER_MAGIC);
        b[8..10].copy_from_slice(&self.major.to_le_bytes());
        b[10..12].copy_from_slice(&self.minor.to_le_bytes());
        b[12..16].copy_from_slice(&self.flags.to_le_bytes());
        b[16..24].copy_from_slice(&self.index_offset.to_le_bytes());
        b[24..32].copy_from_slice(&self.index_copy_offset.to_le_bytes());
        b[32..40].copy_from_slice(&self.recovery_offset.to_le_bytes());
        b[40..48].copy_from_slice(&self.generation.to_le_bytes());
        b[48..56].copy_from_slice(&self.key_info_offset.to_le_bytes());
        let crc = crc32c::crc32c(&b[..60]);
        b[60..64].copy_from_slice(&crc.to_le_bytes());
        b
    }

    pub fn decode(b: &[u8]) -> Result<Footer> {
        if b.len() < FOOTER_LEN || b[0..8] != FOOTER_MAGIC {
            return Err(corrupt("footer magic missing"));
        }
        let crc = u32::from_le_bytes(b[60..64].try_into().unwrap());
        if crc != crc32c::crc32c(&b[..60]) {
            return Err(corrupt("footer checksum"));
        }
        let footer = Footer {
            major: u16::from_le_bytes(b[8..10].try_into().unwrap()),
            minor: u16::from_le_bytes(b[10..12].try_into().unwrap()),
            flags: u32::from_le_bytes(b[12..16].try_into().unwrap()),
            index_offset: u64::from_le_bytes(b[16..24].try_into().unwrap()),
            index_copy_offset: u64::from_le_bytes(b[24..32].try_into().unwrap()),
            recovery_offset: u64::from_le_bytes(b[32..40].try_into().unwrap()),
            generation: u64::from_le_bytes(b[40..48].try_into().unwrap()),
            key_info_offset: u64::from_le_bytes(b[48..56].try_into().unwrap()),
        };
        if footer.major != FORMAT_MAJOR {
            return Err(Error::UnsupportedVersion(footer.major, footer.minor));
        }
        Ok(footer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let f = Footer {
            major: 1,
            minor: 0,
            flags: 2,
            index_offset: 100,
            index_copy_offset: 200,
            recovery_offset: 0,
            generation: 1,
            key_info_offset: 77,
        };
        let mut b = f.encode();
        assert_eq!(Footer::decode(&b).unwrap(), f);
        b[17] ^= 1;
        assert!(Footer::decode(&b).is_err());
    }
}
