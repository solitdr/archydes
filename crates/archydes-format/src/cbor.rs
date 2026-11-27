//! The CBOR subset used by Archydes (RFC 8949), with deterministic encoding (§4.2.1).
//!
//! Allowed: unsigned and negative integers, byte strings, text strings, arrays, maps, `false`,
//! `true`, `null`, all with definite lengths. No tags, no floats, no indefinite lengths.
//! The encoder always writes the shortest form and sorts map keys by their encoded bytes.
//! The decoder accepts non-shortest forms and unsorted keys, never allocates more than the
//! input can hold, and limits nesting.

use crate::consts::limits::MAX_CBOR_DEPTH;
use crate::error::{Error, Result, corrupt};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    Uint(u64),
    /// The negative integer `-1 - n`.
    Nint(u64),
    Bytes(Vec<u8>),
    Text(String),
    Array(Vec<Value>),
    Map(Vec<(Value, Value)>),
    Bool(bool),
    Null,
}

impl Value {
    pub fn int(v: i64) -> Value {
        if v >= 0 { Value::Uint(v as u64) } else { Value::Nint(!(v as u64)) }
    }

    pub fn text(s: impl Into<String>) -> Value {
        Value::Text(s.into())
    }

    /// A map with text keys, the usual shape in the index.
    pub fn map<const N: usize>(pairs: [(&str, Value); N]) -> Value {
        Value::Map(pairs.into_iter().map(|(k, v)| (Value::text(k), v)).collect())
    }

    pub fn as_u64(&self) -> Option<u64> {
        match self {
            Value::Uint(v) => Some(*v),
            _ => None,
        }
    }

    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Value::Uint(v) => i64::try_from(*v).ok(),
            Value::Nint(n) => (*n <= i64::MAX as u64).then(|| -1 - *n as i64),
            _ => None,
        }
    }

    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Value::Bytes(b) => Some(b),
            _ => None,
        }
    }

    pub fn as_text(&self) -> Option<&str> {
        match self {
            Value::Text(s) => Some(s),
            _ => None,
        }
    }

    pub fn as_array(&self) -> Option<&[Value]> {
        match self {
            Value::Array(a) => Some(a),
            _ => None,
        }
    }

    pub fn as_map(&self) -> Option<&[(Value, Value)]> {
        match self {
            Value::Map(m) => Some(m),
            _ => None,
        }
    }

    /// Value for a text key in a map.
    pub fn get(&self, key: &str) -> Option<&Value> {
        self.as_map()?.iter().find(|(k, _)| k.as_text() == Some(key)).map(|(_, v)| v)
    }
}

// ---------------------------------------------------------------------------------------------
// Encoding

pub fn encode(value: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    encode_into(value, &mut out);
    out
}

pub fn encode_into(value: &Value, out: &mut Vec<u8>) {
    match value {
        Value::Uint(v) => head(out, 0, *v),
        Value::Nint(n) => head(out, 1, *n),
        Value::Bytes(b) => {
            head(out, 2, b.len() as u64);
            out.extend_from_slice(b);
        }
        Value::Text(s) => {
            head(out, 3, s.len() as u64);
            out.extend_from_slice(s.as_bytes());
        }
        Value::Array(items) => {
            head(out, 4, items.len() as u64);
            for item in items {
                encode_into(item, out);
            }
        }
        Value::Map(pairs) => {
            let mut encoded: Vec<(Vec<u8>, &Value)> = pairs.iter().map(|(k, v)| (encode(k), v)).collect();
            encoded.sort_by(|a, b| a.0.cmp(&b.0));
            debug_assert!(encoded.windows(2).all(|w| w[0].0 != w[1].0), "duplicate map key");
            head(out, 5, encoded.len() as u64);
            for (key, v) in encoded {
                out.extend_from_slice(&key);
                encode_into(v, out);
            }
        }
        Value::Bool(false) => out.push(0xf4),
        Value::Bool(true) => out.push(0xf5),
        Value::Null => out.push(0xf6),
    }
}

fn head(out: &mut Vec<u8>, major: u8, n: u64) {
    let m = major << 5;
    if n < 24 {
        out.push(m | n as u8);
    } else if n <= u8::MAX as u64 {
        out.extend_from_slice(&[m | 24, n as u8]);
    } else if n <= u16::MAX as u64 {
        out.push(m | 25);
        out.extend_from_slice(&(n as u16).to_be_bytes());
    } else if n <= u32::MAX as u64 {
        out.push(m | 26);
        out.extend_from_slice(&(n as u32).to_be_bytes());
    } else {
        out.push(m | 27);
        out.extend_from_slice(&n.to_be_bytes());
    }
}

// ---------------------------------------------------------------------------------------------
// Decoding

/// Decodes exactly one value that fills `bytes` completely.
pub fn decode(bytes: &[u8]) -> Result<Value> {
    let mut d = Decoder { b: bytes, pos: 0 };
    let v = d.value(0)?;
    if d.pos != bytes.len() {
        return Err(corrupt("trailing bytes after CBOR value"));
    }
    Ok(v)
}

/// Decodes one value at the start of `bytes`; returns it and the number of bytes used.
pub fn decode_prefix(bytes: &[u8]) -> Result<(Value, usize)> {
    let mut d = Decoder { b: bytes, pos: 0 };
    let v = d.value(0)?;
    Ok((v, d.pos))
}

struct Decoder<'a> {
    b: &'a [u8],
    pos: usize,
}

impl Decoder<'_> {
    fn byte(&mut self) -> Result<u8> {
        let v = *self.b.get(self.pos).ok_or_else(|| corrupt("CBOR truncated"))?;
        self.pos += 1;
        Ok(v)
    }

    fn take(&mut self, n: u64) -> Result<&[u8]> {
        let remaining = (self.b.len() - self.pos) as u64;
        if n > remaining {
            return Err(corrupt("CBOR length beyond input"));
        }
        let start = self.pos;
        self.pos += n as usize;
        Ok(&self.b[start..self.pos])
    }

    fn argument(&mut self, info: u8) -> Result<u64> {
        Ok(match info {
            0..=23 => info as u64,
            24 => self.byte()? as u64,
            25 => u16::from_be_bytes(self.take(2)?.try_into().unwrap()) as u64,
            26 => u32::from_be_bytes(self.take(4)?.try_into().unwrap()) as u64,
            27 => u64::from_be_bytes(self.take(8)?.try_into().unwrap()),
            31 => return Err(Error::Unsupported("CBOR indefinite length".into())),
            _ => return Err(corrupt("CBOR reserved additional information")),
        })
    }

    /// Item counts can not exceed the remaining bytes (every item takes at least one byte).
    fn count(&mut self, n: u64, per_item: u64) -> Result<usize> {
        let remaining = (self.b.len() - self.pos) as u64;
        if n.saturating_mul(per_item) > remaining {
            return Err(corrupt("CBOR item count beyond input"));
        }
        Ok(n as usize)
    }

    fn value(&mut self, depth: usize) -> Result<Value> {
        if depth > MAX_CBOR_DEPTH {
            return Err(Error::Limit("CBOR nesting too deep".into()));
        }
        let initial = self.byte()?;
        let major = initial >> 5;
        let info = initial & 0x1f;
        match major {
            0 => Ok(Value::Uint(self.argument(info)?)),
            1 => Ok(Value::Nint(self.argument(info)?)),
            2 => {
                let n = self.argument(info)?;
                Ok(Value::Bytes(self.take(n)?.to_vec()))
            }
            3 => {
                let n = self.argument(info)?;
                let raw = self.take(n)?;
                let s = std::str::from_utf8(raw).map_err(|_| corrupt("CBOR text is not UTF-8"))?;
                Ok(Value::Text(s.to_owned()))
            }
            4 => {
                let n = self.argument(info)?;
                let n = self.count(n, 1)?;
                let mut items = Vec::with_capacity(n);
                for _ in 0..n {
                    items.push(self.value(depth + 1)?);
                }
                Ok(Value::Array(items))
            }
            5 => {
                let n = self.argument(info)?;
                let n = self.count(n, 2)?;
                let mut pairs = Vec::with_capacity(n);
                for _ in 0..n {
                    let k = self.value(depth + 1)?;
                    let v = self.value(depth + 1)?;
                    pairs.push((k, v));
                }
                Ok(Value::Map(pairs))
            }
            6 => Err(Error::Unsupported("CBOR tags".into())),
            _ => match info {
                20 => Ok(Value::Bool(false)),
                21 => Ok(Value::Bool(true)),
                22 => Ok(Value::Null),
                _ => Err(Error::Unsupported("CBOR floats and simple values".into())),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shortest_heads() {
        assert_eq!(encode(&Value::Uint(23)), [0x17]);
        assert_eq!(encode(&Value::Uint(24)), [0x18, 24]);
        assert_eq!(encode(&Value::Uint(1000)), [0x19, 0x03, 0xe8]);
        assert_eq!(encode(&Value::int(-1)), [0x20]);
        assert_eq!(encode(&Value::int(-1000)), [0x39, 0x03, 0xe7]);
        assert_eq!(Value::int(i64::MIN).as_i64(), Some(i64::MIN));
    }

    #[test]
    fn map_keys_sorted_by_encoding() {
        // RFC 8949 §4.2.1: shorter keys first, then bytewise.
        let v = Value::map([("bb", Value::Uint(1)), ("a", Value::Uint(2)), ("c", Value::Uint(3))]);
        let e = encode(&v);
        assert_eq!(e, [0xa3, 0x61, b'a', 2, 0x61, b'c', 3, 0x62, b'b', b'b', 1]);
        assert_eq!(decode(&e).unwrap().get("bb"), Some(&Value::Uint(1)));
    }

    #[test]
    fn round_trip() {
        let v = Value::Array(vec![
            Value::Bytes(vec![1, 2, 3]),
            Value::text("Größe"),
            Value::Map(vec![(Value::Uint(1), Value::Null), (Value::Uint(0), Value::Bool(true))]),
            Value::int(-5),
        ]);
        assert_eq!(
            decode(&encode(&v)).unwrap(),
            Value::Array(vec![
                Value::Bytes(vec![1, 2, 3]),
                Value::text("Größe"),
                Value::Map(vec![(Value::Uint(0), Value::Bool(true)), (Value::Uint(1), Value::Null)]),
                Value::int(-5),
            ])
        );
    }

    #[test]
    fn hostile_input() {
        // Byte string claiming 2^64-1 bytes.
        assert!(decode(&[0x5b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]).is_err());
        // Array claiming 2^32 items.
        assert!(decode(&[0x9a, 0xff, 0xff, 0xff, 0xff]).is_err());
        // Deep nesting.
        assert!(decode(&[0x81; 100]).is_err());
        // Trailing data, truncation, invalid UTF-8, tags, floats.
        assert!(decode(&[0x01, 0x02]).is_err());
        assert!(decode(&[0x19, 0x01]).is_err());
        assert!(decode(&[0x62, 0xff, 0xfe]).is_err());
        assert!(decode(&[0xc0, 0x01]).is_err());
        assert!(decode(&[0xf9, 0, 0]).is_err());
    }
}
