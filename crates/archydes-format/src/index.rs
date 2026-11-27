//! The index (SPEC A6): pack table, chunk table and all snapshots.
//!
//! [`Index::from_value`] checks every reference (pack numbers, chunk ranges, stream indices), so
//! code that reads an index never has to check them again.

use std::io::Read;

use crate::cbor::{self, Value};
use crate::consts::{index_codec, limits};
use crate::error::{Error, Result, corrupt};

pub const INDEX_VERSION: u64 = 1;

/// Indices into the chunk table.
pub type Stream = Vec<u32>;

/// Original file = concatenation of the parts' outputs.
pub type Recipe = Vec<Part>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Part {
    pub transform: u64,
    /// Transformation parameters, a CBOR map (empty for RAW).
    pub params: Vec<(Value, Value)>,
    pub inputs: Vec<Stream>,
}

impl Part {
    pub fn raw(stream: Stream) -> Part {
        Part { transform: crate::consts::transform::RAW, params: Vec::new(), inputs: vec![stream] }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CdcParams {
    pub min: u64,
    pub avg: u64,
    pub max: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PackRef {
    /// Offset of the PACK segment header.
    pub off: u64,
    /// Length of the compressed data (payload without the pack header).
    pub clen: u64,
    pub ulen: u64,
    pub codec: u64,
    /// BLAKE3-128 of the whole segment payload, equal to the segment header's hash.
    pub hash: [u8; 16],
}

/// The chunk table, stored by columns.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ChunkTable {
    pub ids: Vec<[u8; 32]>,
    pub pack: Vec<u32>,
    pub off: Vec<u64>,
    pub len: Vec<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Chunk {
    pub id: [u8; 32],
    pub pack: u32,
    pub off: u64,
    pub len: u64,
}

impl ChunkTable {
    pub fn len(&self) -> usize {
        self.ids.len()
    }

    pub fn is_empty(&self) -> bool {
        self.ids.is_empty()
    }

    pub fn get(&self, i: u32) -> Chunk {
        let i = i as usize;
        Chunk { id: self.ids[i], pack: self.pack[i], off: self.off[i], len: self.len[i] }
    }

    pub fn push(&mut self, chunk: Chunk) -> u32 {
        let i = self.ids.len() as u32;
        self.ids.push(chunk.id);
        self.pack.push(chunk.pack);
        self.off.push(chunk.off);
        self.len.push(chunk.len);
        i
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryKind {
    File,
    Directory,
    Symlink,
    Hardlink,
}

impl EntryKind {
    fn code(self) -> u64 {
        match self {
            EntryKind::File => 0,
            EntryKind::Directory => 1,
            EntryKind::Symlink => 2,
            EntryKind::Hardlink => 3,
        }
    }

    fn from_code(code: u64) -> Option<Self> {
        Some(match code {
            0 => EntryKind::File,
            1 => EntryKind::Directory,
            2 => EntryKind::Symlink,
            3 => EntryKind::Hardlink,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// Path bytes as the file system delivered them, `/`-separated, relative.
    pub path: Vec<u8>,
    /// NFC form for display and comparison.
    pub path_nfc: String,
    pub kind: EntryKind,
    pub mode: u32,
    pub mtime_ns: i64,
    pub btime_ns: Option<i64>,
    pub xattrs: Vec<(String, Stream)>,
    /// Symlink target, or the path of the hardlink's original.
    pub target: Option<Vec<u8>>,
    /// Size of the original file (files only).
    pub size: u64,
    /// BLAKE3-256 of the original file (files only).
    pub hash: Option<[u8; 32]>,
    /// Files only.
    pub recipe: Option<Recipe>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Snapshot {
    pub id: u64,
    pub time_ns: i64,
    pub comment: String,
    pub source: String,
    pub entries: Vec<Entry>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Index {
    pub version: u64,
    pub generation: u64,
    pub created_ns: i64,
    pub cdc: Option<CdcParams>,
    pub packs: Vec<PackRef>,
    pub chunks: ChunkTable,
    pub snapshots: Vec<Snapshot>,
}

// ---------------------------------------------------------------------------------------------
// To CBOR

fn stream_value(s: &Stream) -> Value {
    Value::Array(s.iter().map(|&i| Value::Uint(i as u64)).collect())
}

impl Index {
    pub fn to_value(&self) -> Value {
        let packs = self
            .packs
            .iter()
            .map(|p| {
                Value::map([
                    ("off", Value::Uint(p.off)),
                    ("clen", Value::Uint(p.clen)),
                    ("ulen", Value::Uint(p.ulen)),
                    ("codec", Value::Uint(p.codec)),
                    ("hash", Value::Bytes(p.hash.to_vec())),
                ])
            })
            .collect();
        let c = &self.chunks;
        let chunks = Value::map([
            ("id", Value::Bytes(c.ids.iter().flatten().copied().collect())),
            ("pack", Value::Array(c.pack.iter().map(|&p| Value::Uint(p as u64)).collect())),
            ("off", Value::Array(c.off.iter().map(|&o| Value::Uint(o)).collect())),
            ("len", Value::Array(c.len.iter().map(|&l| Value::Uint(l)).collect())),
        ]);
        let mut pairs = vec![
            (Value::text("v"), Value::Uint(self.version)),
            (Value::text("generation"), Value::Uint(self.generation)),
            (Value::text("created_ns"), Value::int(self.created_ns)),
            (Value::text("packs"), Value::Array(packs)),
            (Value::text("chunks"), chunks),
            (Value::text("snapshots"), Value::Array(self.snapshots.iter().map(snapshot_value).collect())),
        ];
        if let Some(cdc) = self.cdc {
            pairs.push((
                Value::text("cdc"),
                Value::map([
                    ("alg", Value::text("fastcdc-2020")),
                    ("min", Value::Uint(cdc.min)),
                    ("avg", Value::Uint(cdc.avg)),
                    ("max", Value::Uint(cdc.max)),
                ]),
            ));
        }
        Value::Map(pairs)
    }

    /// Segment payload: codec byte (1 = zstd) followed by the compressed CBOR.
    pub fn encode_payload(&self) -> Vec<u8> {
        let cbor = cbor::encode(&self.to_value());
        let mut out = vec![index_codec::ZSTD];
        out.extend(zstd::bulk::compress(&cbor, 19).expect("zstd compression of the index"));
        out
    }

    pub fn decode_payload(payload: &[u8]) -> Result<Index> {
        let (&codec, data) = payload.split_first().ok_or_else(|| corrupt("empty index"))?;
        if codec != index_codec::ZSTD {
            return Err(Error::Unsupported(format!("index codec {codec}")));
        }
        let mut decoder = zstd::stream::read::Decoder::new(data).map_err(|e| corrupt(format!("index: {e}")))?;
        let mut cbor = Vec::new();
        (&mut decoder)
            .take(limits::MAX_INDEX_ULEN + 1)
            .read_to_end(&mut cbor)
            .map_err(|e| corrupt(format!("index decompression: {e}")))?;
        if cbor.len() as u64 > limits::MAX_INDEX_ULEN {
            return Err(Error::Limit("index larger than 1 GiB".into()));
        }
        Index::from_value(&cbor::decode(&cbor)?)
    }
}

fn snapshot_value(s: &Snapshot) -> Value {
    Value::map([
        ("id", Value::Uint(s.id)),
        ("time_ns", Value::int(s.time_ns)),
        ("comment", Value::text(s.comment.clone())),
        ("source", Value::text(s.source.clone())),
        ("entries", Value::Array(s.entries.iter().map(entry_value).collect())),
    ])
}

fn entry_value(e: &Entry) -> Value {
    let mut pairs = vec![
        (Value::text("path"), Value::Bytes(e.path.clone())),
        (Value::text("path_nfc"), Value::text(e.path_nfc.clone())),
        (Value::text("kind"), Value::Uint(e.kind.code())),
        (Value::text("mode"), Value::Uint(e.mode as u64)),
        (Value::text("mtime_ns"), Value::int(e.mtime_ns)),
    ];
    if let Some(b) = e.btime_ns {
        pairs.push((Value::text("btime_ns"), Value::int(b)));
    }
    if !e.xattrs.is_empty() {
        let map = e.xattrs.iter().map(|(k, s)| (Value::text(k.clone()), stream_value(s))).collect();
        pairs.push((Value::text("xattr"), Value::Map(map)));
    }
    if let Some(t) = &e.target {
        pairs.push((Value::text("target"), Value::Bytes(t.clone())));
    }
    if e.kind == EntryKind::File {
        pairs.push((Value::text("size"), Value::Uint(e.size)));
        if let Some(h) = e.hash {
            pairs.push((Value::text("hash"), Value::Bytes(h.to_vec())));
        }
        if let Some(r) = &e.recipe {
            let parts = r
                .iter()
                .map(|p| {
                    Value::Array(vec![
                        Value::Uint(p.transform),
                        Value::Map(p.params.clone()),
                        Value::Array(p.inputs.iter().map(stream_value).collect()),
                    ])
                })
                .collect();
            pairs.push((Value::text("recipe"), Value::Array(parts)));
        }
    }
    Value::Map(pairs)
}

// ---------------------------------------------------------------------------------------------
// From CBOR, with validation

fn need<'a>(map: &'a Value, key: &str, what: &str) -> Result<&'a Value> {
    map.get(key).ok_or_else(|| corrupt(format!("{what}: \"{key}\" missing")))
}

fn need_u64(map: &Value, key: &str, what: &str) -> Result<u64> {
    need(map, key, what)?.as_u64().ok_or_else(|| corrupt(format!("{what}: \"{key}\" is not an unsigned integer")))
}

fn need_i64(map: &Value, key: &str, what: &str) -> Result<i64> {
    need(map, key, what)?.as_i64().ok_or_else(|| corrupt(format!("{what}: \"{key}\" is not an integer")))
}

fn need_array<'a>(map: &'a Value, key: &str, what: &str) -> Result<&'a [Value]> {
    need(map, key, what)?.as_array().ok_or_else(|| corrupt(format!("{what}: \"{key}\" is not an array")))
}

fn opt_text(map: &Value, key: &str) -> String {
    map.get(key).and_then(Value::as_text).unwrap_or_default().to_owned()
}

fn u64_column(map: &Value, key: &str) -> Result<Vec<u64>> {
    need_array(map, key, "chunk table")?
        .iter()
        .map(|v| v.as_u64().ok_or_else(|| corrupt(format!("chunk table: \"{key}\" holds a non-integer"))))
        .collect()
}

fn stream_from(v: &Value, chunk_count: usize, what: &str) -> Result<Stream> {
    let items = v.as_array().ok_or_else(|| corrupt(format!("{what}: stream is not an array")))?;
    items
        .iter()
        .map(|i| match i.as_u64() {
            Some(n) if n < chunk_count as u64 => Ok(n as u32),
            _ => Err(corrupt(format!("{what}: stream refers to a missing chunk"))),
        })
        .collect()
}

impl Index {
    pub fn from_value(v: &Value) -> Result<Index> {
        if v.as_map().is_none() {
            return Err(corrupt("index is not a map"));
        }
        let version = need_u64(v, "v", "index")?;
        if version != INDEX_VERSION {
            return Err(Error::Unsupported(format!("index version {version}")));
        }

        let mut packs = Vec::new();
        for p in need_array(v, "packs", "index")? {
            let hash = need(p, "hash", "pack")?
                .as_bytes()
                .and_then(|b| <[u8; 16]>::try_from(b).ok())
                .ok_or_else(|| corrupt("pack: hash must be 16 bytes"))?;
            let pack = PackRef {
                off: need_u64(p, "off", "pack")?,
                clen: need_u64(p, "clen", "pack")?,
                ulen: need_u64(p, "ulen", "pack")?,
                codec: need_u64(p, "codec", "pack")?,
                hash,
            };
            if pack.ulen > limits::MAX_PACK_ULEN {
                return Err(Error::Limit(format!("pack of {} bytes", pack.ulen)));
            }
            packs.push(pack);
        }
        if packs.len() > u32::MAX as usize {
            return Err(Error::Limit("too many packs".into()));
        }

        let c = need(v, "chunks", "index")?;
        let ids_raw =
            need(c, "id", "chunk table")?.as_bytes().ok_or_else(|| corrupt("chunk table: id is not bytes"))?;
        if ids_raw.len() % 32 != 0 {
            return Err(corrupt("chunk table: id length is not a multiple of 32"));
        }
        let ids: Vec<[u8; 32]> = ids_raw.as_chunks::<32>().0.to_vec();
        let pack = u64_column(c, "pack")?;
        let off = u64_column(c, "off")?;
        let len = u64_column(c, "len")?;
        let n = ids.len();
        if pack.len() != n || off.len() != n || len.len() != n || n > u32::MAX as usize {
            return Err(corrupt("chunk table: columns differ in length"));
        }
        for i in 0..n {
            let p = packs.get(pack[i] as usize).ok_or_else(|| corrupt("chunk refers to a missing pack"))?;
            match off[i].checked_add(len[i]) {
                Some(end) if end <= p.ulen => {}
                _ => return Err(corrupt("chunk lies outside its pack")),
            }
        }
        let chunks = ChunkTable { ids, pack: pack.into_iter().map(|p| p as u32).collect(), off, len };

        let cdc = match v.get("cdc") {
            Some(cdc) => Some(CdcParams {
                min: need_u64(cdc, "min", "cdc")?,
                avg: need_u64(cdc, "avg", "cdc")?,
                max: need_u64(cdc, "max", "cdc")?,
            }),
            None => None,
        };

        let mut snapshots = Vec::new();
        for s in need_array(v, "snapshots", "index")? {
            let mut entries = Vec::new();
            for e in need_array(s, "entries", "snapshot")? {
                entries.push(entry_from(e, n)?);
            }
            snapshots.push(Snapshot {
                id: need_u64(s, "id", "snapshot")?,
                time_ns: need_i64(s, "time_ns", "snapshot")?,
                comment: opt_text(s, "comment"),
                source: opt_text(s, "source"),
                entries,
            });
        }

        Ok(Index {
            version,
            generation: need_u64(v, "generation", "index")?,
            created_ns: need_i64(v, "created_ns", "index")?,
            cdc,
            packs,
            chunks,
            snapshots,
        })
    }
}

fn entry_from(e: &Value, chunk_count: usize) -> Result<Entry> {
    let what = "entry";
    let path = need(e, "path", what)?.as_bytes().ok_or_else(|| corrupt("entry: path is not bytes"))?.to_vec();
    let kind = EntryKind::from_code(need_u64(e, "kind", what)?).ok_or_else(|| corrupt("entry: unknown kind"))?;
    let mode = u32::try_from(need_u64(e, "mode", what)?).map_err(|_| corrupt("entry: mode too large"))?;
    let path_nfc = match e.get("path_nfc").and_then(Value::as_text) {
        Some(s) => s.to_owned(),
        None => String::from_utf8_lossy(&path).into_owned(),
    };
    let btime_ns = match e.get("btime_ns") {
        Some(b) => Some(b.as_i64().ok_or_else(|| corrupt("entry: btime_ns is not an integer"))?),
        None => None,
    };
    let mut xattrs = Vec::new();
    if let Some(x) = e.get("xattr") {
        for (k, s) in x.as_map().ok_or_else(|| corrupt("entry: xattr is not a map"))? {
            let name = k.as_text().ok_or_else(|| corrupt("entry: xattr name is not text"))?;
            xattrs.push((name.to_owned(), stream_from(s, chunk_count, "xattr")?));
        }
    }
    let target = match e.get("target") {
        Some(t) => Some(t.as_bytes().ok_or_else(|| corrupt("entry: target is not bytes"))?.to_vec()),
        None => None,
    };
    if matches!(kind, EntryKind::Symlink | EntryKind::Hardlink) && target.is_none() {
        return Err(corrupt("link without target"));
    }

    let (mut size, mut hash, mut recipe) = (0, None, None);
    if kind == EntryKind::File {
        size = need_u64(e, "size", what)?;
        hash = Some(
            need(e, "hash", what)?
                .as_bytes()
                .and_then(|b| <[u8; 32]>::try_from(b).ok())
                .ok_or_else(|| corrupt("entry: hash must be 32 bytes"))?,
        );
        let mut parts = Vec::new();
        for p in need_array(e, "recipe", what)? {
            let items = p.as_array().filter(|a| a.len() == 3).ok_or_else(|| corrupt("recipe part is not a triple"))?;
            let transform = items[0].as_u64().ok_or_else(|| corrupt("recipe: transformation id"))?;
            let params = items[1].as_map().ok_or_else(|| corrupt("recipe: params is not a map"))?.to_vec();
            let inputs = items[2]
                .as_array()
                .ok_or_else(|| corrupt("recipe: inputs is not an array"))?
                .iter()
                .map(|s| stream_from(s, chunk_count, "recipe"))
                .collect::<Result<Vec<_>>>()?;
            parts.push(Part { transform, params, inputs });
        }
        recipe = Some(parts);
    }

    Ok(Entry {
        path,
        path_nfc,
        kind,
        mode,
        mtime_ns: need_i64(e, "mtime_ns", what)?,
        btime_ns,
        xattrs,
        target,
        size,
        hash,
        recipe,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(crate) fn sample() -> Index {
        let mut chunks = ChunkTable::default();
        chunks.push(Chunk { id: [1; 32], pack: 0, off: 0, len: 10 });
        chunks.push(Chunk { id: [2; 32], pack: 0, off: 10, len: 5 });
        let file = Entry {
            path: "a/b.txt".into(),
            path_nfc: "a/b.txt".into(),
            kind: EntryKind::File,
            mode: 0o644,
            mtime_ns: 1_700_000_000_123_456_789,
            btime_ns: Some(-3),
            xattrs: vec![("com.apple.FinderInfo".into(), vec![1])],
            target: None,
            size: 15,
            hash: Some([9; 32]),
            recipe: Some(vec![Part::raw(vec![0, 1])]),
        };
        let link = Entry {
            path: "a/l".into(),
            path_nfc: "a/l".into(),
            kind: EntryKind::Symlink,
            mode: 0o755,
            mtime_ns: 0,
            btime_ns: None,
            xattrs: vec![],
            target: Some("b.txt".into()),
            size: 0,
            hash: None,
            recipe: None,
        };
        Index {
            version: 1,
            generation: 1,
            created_ns: 42,
            cdc: Some(CdcParams { min: 65536, avg: 262144, max: 1048576 }),
            packs: vec![PackRef { off: 64, clen: 12, ulen: 15, codec: 1, hash: [5; 16] }],
            chunks,
            snapshots: vec![Snapshot {
                id: 1,
                time_ns: 42,
                comment: String::new(),
                source: "/x".into(),
                entries: vec![file, link],
            }],
        }
    }

    #[test]
    fn round_trip() {
        let index = sample();
        let payload = index.encode_payload();
        assert_eq!(Index::decode_payload(&payload).unwrap(), index);
        // Deterministic.
        assert_eq!(payload, index.encode_payload());
    }

    #[test]
    fn rejects_bad_references() {
        let mut index = sample();
        index.chunks.len[1] = 6; // beyond pack ulen 15
        assert!(Index::from_value(&index.to_value()).is_err());

        let mut index = sample();
        index.snapshots[0].entries[0].recipe = Some(vec![Part::raw(vec![0, 7])]);
        assert!(Index::from_value(&index.to_value()).is_err());

        let mut index = sample();
        index.chunks.pack[0] = 3;
        assert!(Index::from_value(&index.to_value()).is_err());
    }
}
