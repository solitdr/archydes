//! Reading streams and files out of an opened archive.

use std::collections::{HashSet, VecDeque};
use std::io::{self, Write};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};

use archydes_format::{Archive, Entry, EntryKind, Error, ReadAt, Result, Stream, corrupt};

use crate::codec;

/// Decoded packs, and the packs another thread is decoding right now.
#[derive(Default)]
struct Cache {
    packs: VecDeque<(u32, Arc<Vec<u8>>)>,
    decoding: HashSet<u32>,
}

/// An archive opened for reading, with a small cache of decompressed packs.
pub struct Reader<R: ReadAt> {
    pub archive: Archive<R>,
    cache: Mutex<Cache>,
    /// Signalled when a pack has been decoded.
    decoded: Condvar,
    cache_slots: usize,
    /// The pack last asked for through [`Reader::pack`] (+1; 0 = none), for prefetching.
    last: AtomicU64,
}

impl<R: ReadAt> Reader<R> {
    pub fn open(src: R) -> Result<Self> {
        Ok(Self::new(Archive::open(src)?))
    }

    /// Opens an archive that may be encrypted (SPEC A11).
    pub fn open_with(src: R, password: Option<&str>) -> Result<Self> {
        Ok(Self::new(Archive::open_with(src, password)?))
    }

    /// Opens an encrypted archive with keys unlocked before.
    pub fn open_with_keys(src: R, keys: archydes_format::Keys) -> Result<Self> {
        Ok(Self::new(Archive::open_with_keys(src, keys)?))
    }

    pub fn new(archive: Archive<R>) -> Self {
        let slots = std::thread::available_parallelism().map_or(4, |n| n.get()).clamp(4, 16);
        Reader {
            archive,
            cache: Mutex::new(Cache::default()),
            decoded: Condvar::new(),
            cache_slots: slots,
            last: AtomicU64::new(0),
        }
    }

    /// Reads and decompresses pack `i` without the cache.
    pub fn decode_pack(&self, i: u32) -> Result<Vec<u8>> {
        let (header, data) = self.archive.read_pack(i as usize)?;
        codec::decompress(&header, data).map_err(|e| match e {
            Error::Corrupt(m) => corrupt(format!("pack {i}: {m}")),
            other => other,
        })
    }

    /// Decompressed pack `i`, from the cache if possible.
    pub fn pack(&self, i: u32) -> Result<Arc<Vec<u8>>> {
        self.last.store(u64::from(i) + 1, Ordering::Relaxed);
        self.cached_pack(i)
    }

    /// Puts pack `i` into the cache without counting as a request (see `extract`).
    pub fn prefetch(&self, i: u32) -> Result<()> {
        self.cached_pack(i).map(|_| ())
    }

    /// How many packs the cache holds.
    pub fn cache_slots(&self) -> usize {
        self.cache_slots
    }

    /// The pack last asked for through [`Reader::pack`].
    pub fn last_requested(&self) -> Option<u32> {
        self.last.load(Ordering::Relaxed).checked_sub(1).map(|i| i as u32)
    }

    /// From the cache; a pack another thread is decoding is waited for, not decoded twice.
    fn cached_pack(&self, i: u32) -> Result<Arc<Vec<u8>>> {
        let lock = || self.cache.lock().unwrap_or_else(|e| e.into_inner());
        let mut cache = lock();
        loop {
            if let Some((_, hit)) = cache.packs.iter().find(|(n, _)| *n == i) {
                return Ok(hit.clone());
            }
            if !cache.decoding.contains(&i) {
                break;
            }
            cache = self.decoded.wait(cache).unwrap_or_else(|e| e.into_inner());
        }
        cache.decoding.insert(i);
        drop(cache);
        let result = self.decode_pack(i).map(Arc::new);
        let mut cache = lock();
        cache.decoding.remove(&i);
        if let Ok(data) = &result {
            if cache.packs.len() >= self.cache_slots {
                cache.packs.pop_front();
            }
            cache.packs.push_back((i, data.clone()));
        }
        drop(cache);
        self.decoded.notify_all();
        result
    }

    /// Hands the chunks of `stream` to `sink`. With `check`, every chunk is compared with its
    /// ID (BLAKE3-256, keyed when encrypted).
    pub fn read_stream(&self, stream: &Stream, check: bool, sink: &mut dyn FnMut(&[u8]) -> Result<()>) -> Result<()> {
        let table = &self.archive.index.chunks;
        for &c in stream {
            let chunk = table.get(c);
            let pack = self.pack(chunk.pack)?;
            // Ranges were checked against the pack length when the index was read.
            let data = &pack[chunk.off as usize..(chunk.off + chunk.len) as usize];
            if check && self.archive.chunk_id(data) != chunk.id {
                return Err(corrupt(format!("chunk {c} does not match its ID")));
            }
            sink(data)?;
        }
        Ok(())
    }

    /// The whole content of a (small) stream, checked; used for extended attributes.
    pub fn stream_bytes(&self, stream: &Stream) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        self.read_stream(stream, true, &mut |d| {
            out.extend_from_slice(d);
            Ok(())
        })?;
        Ok(out)
    }

    /// Rebuilds a file from its recipe into `out`; checks size and BLAKE3 hash.
    /// Stops as soon as more data than the declared size would be written (bomb protection).
    pub fn write_file(&self, entry: &Entry, out: &mut dyn Write) -> Result<()> {
        if entry.kind != EntryKind::File {
            return Err(corrupt("not a file"));
        }
        let (Some(recipe), Some(hash)) = (&entry.recipe, entry.hash) else {
            return Err(corrupt("file without recipe"));
        };
        let mut hasher = blake3::Hasher::new();
        let mut written = 0u64;
        let mut sink = |data: &[u8]| -> Result<()> {
            written += data.len() as u64;
            if written > entry.size {
                return Err(corrupt("file larger than declared"));
            }
            hasher.update(data);
            out.write_all(data).map_err(Error::Io)
        };
        for part in recipe {
            crate::transform::rebuild_part(
                part,
                &mut |k, input_sink| self.read_stream(&part.inputs[k], false, input_sink),
                &mut sink,
            )?;
        }
        if written != entry.size {
            return Err(corrupt("file smaller than declared"));
        }
        if *hasher.finalize().as_bytes() != hash {
            return Err(corrupt("file does not match its hash"));
        }
        Ok(())
    }

    /// Where the file's data starts (pack, offset), to read files in pack order.
    pub fn first_location(&self, entry: &Entry) -> (u32, u64) {
        let first = entry.recipe.iter().flatten().flat_map(|p| p.inputs.iter()).flat_map(|s| s.first()).next();
        match first {
            Some(&c) => {
                let chunk = self.archive.index.chunks.get(c);
                (chunk.pack, chunk.off)
            }
            None => (0, 0),
        }
    }

    /// All chunk numbers an entry uses (data and extended attributes).
    pub fn chunks_of<'a>(&self, entry: &'a Entry) -> impl Iterator<Item = u32> + 'a {
        let data = entry.recipe.iter().flatten().flat_map(|p| p.inputs.iter()).flatten();
        let xattrs = entry.xattrs.iter().flat_map(|(_, s)| s.iter());
        data.chain(xattrs).copied()
    }
}

/// A writer that discards everything (for verification).
pub(crate) struct Discard;

impl Write for Discard {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
