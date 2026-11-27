//! PACK payload (SPEC A5.3): `u32` length, CBOR pack header, compressed data.

use crate::cbor::{self, Value};
use crate::consts::{codec, limits};
use crate::error::{Error, Result, corrupt};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PackHeader {
    pub codec: u64,
    /// Uncompressed length.
    pub ulen: u64,
    /// Number of chunks in the pack.
    pub chunks: u64,
    /// Compression level, informative.
    pub level: Option<u64>,
    /// LZMA2 dictionary size (required for LZMA2).
    pub dict: Option<u64>,
}

impl PackHeader {
    pub fn to_value(&self) -> Value {
        let mut pairs = vec![
            (Value::text("codec"), Value::Uint(self.codec)),
            (Value::text("ulen"), Value::Uint(self.ulen)),
            (Value::text("chunks"), Value::Uint(self.chunks)),
        ];
        if let Some(l) = self.level {
            pairs.push((Value::text("level"), Value::Uint(l)));
        }
        if let Some(d) = self.dict {
            pairs.push((Value::text("dict"), Value::Uint(d)));
        }
        Value::Map(pairs)
    }

    /// The bytes in front of the compressed data.
    pub fn encode_prefix(&self) -> Vec<u8> {
        let cbor = cbor::encode(&self.to_value());
        let mut out = Vec::with_capacity(4 + cbor.len());
        out.extend_from_slice(&(cbor.len() as u32).to_le_bytes());
        out.extend(cbor);
        out
    }

    /// Splits a pack payload into header and compressed data.
    pub fn decode_payload(payload: &[u8]) -> Result<(PackHeader, &[u8])> {
        if payload.len() < 4 {
            return Err(corrupt("pack payload truncated"));
        }
        let len = u32::from_le_bytes(payload[..4].try_into().unwrap());
        if len > limits::MAX_PACK_HEADER_LEN || 4 + len as usize > payload.len() {
            return Err(corrupt("pack header length"));
        }
        let v = cbor::decode(&payload[4..4 + len as usize])?;
        let get = |k: &str| v.get(k).and_then(Value::as_u64);
        let header = PackHeader {
            codec: get("codec").ok_or_else(|| corrupt("pack header: codec"))?,
            ulen: get("ulen").ok_or_else(|| corrupt("pack header: ulen"))?,
            chunks: get("chunks").ok_or_else(|| corrupt("pack header: chunks"))?,
            level: get("level"),
            dict: get("dict"),
        };
        if header.ulen > limits::MAX_PACK_ULEN {
            return Err(Error::Limit(format!("pack of {} bytes", header.ulen)));
        }
        if header.codec == codec::LZMA2 && header.dict.is_none() {
            return Err(corrupt("LZMA2 pack without dictionary size"));
        }
        Ok((header, &payload[4 + len as usize..]))
    }
}
