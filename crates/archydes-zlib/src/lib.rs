//! zlib 1.3.1, bundled unchanged (SPEC A7, D-011): the `impl` value `"zlib-1.3.1"`.
//!
//! ZLIB_EXACT stores the inflated data and the zlib parameters; the decoder deflates again and
//! must get exactly the original bytes. That only works with this very zlib version, which is why
//! it is compiled in and never taken from the system.

use std::ffi::{c_char, c_int, c_uint, c_ulong, c_void};
use std::mem::MaybeUninit;

/// The value of `impl` for this zlib.
pub const IMPL: &str = "zlib-1.3.1";
const VERSION: &[u8] = b"1.3.1\0";

#[repr(C)]
struct ZStream {
    next_in: *const u8,
    avail_in: c_uint,
    total_in: c_ulong,
    next_out: *mut u8,
    avail_out: c_uint,
    total_out: c_ulong,
    msg: *const c_char,
    state: *mut c_void,
    zalloc: *const c_void,
    zfree: *const c_void,
    opaque: *mut c_void,
    data_type: c_int,
    adler: c_ulong,
    reserved: c_ulong,
}

const Z_OK: c_int = 0;
const Z_STREAM_END: c_int = 1;
const Z_BUF_ERROR: c_int = -5;
const Z_NO_FLUSH: c_int = 0;
const Z_FINISH: c_int = 4;
const Z_DEFLATED: c_int = 8;

unsafe extern "C" {
    fn z_deflateInit2_(
        s: *mut ZStream,
        level: c_int,
        method: c_int,
        wbits: c_int,
        memlevel: c_int,
        strategy: c_int,
        version: *const c_char,
        size: c_int,
    ) -> c_int;
    fn z_deflate(s: *mut ZStream, flush: c_int) -> c_int;
    fn z_deflateEnd(s: *mut ZStream) -> c_int;
    fn z_inflateInit2_(s: *mut ZStream, wbits: c_int, version: *const c_char, size: c_int) -> c_int;
    fn z_inflate(s: *mut ZStream, flush: c_int) -> c_int;
    fn z_inflateEnd(s: *mut ZStream) -> c_int;
    fn z_zlibVersion() -> *const c_char;
}

/// Parameters of `deflateInit2`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Params {
    /// 8…15 zlib wrapper, −8…−15 raw deflate, 24…31 gzip wrapper.
    pub wbits: i32,
    pub level: i32,
    pub memlevel: i32,
    pub strategy: i32,
}

impl Params {
    pub fn valid(&self) -> bool {
        let w = self.wbits.unsigned_abs();
        let wrapper_ok = (8..=15).contains(&w) || (self.wbits > 0 && (24..=31).contains(&self.wbits));
        // zlib turns raw windowBits 8 into 9, which would not round-trip; refuse it.
        wrapper_ok
            && self.wbits != -8
            && (0..=9).contains(&self.level)
            && (1..=9).contains(&self.memlevel)
            && (0..=4).contains(&self.strategy)
    }
}

#[derive(Debug)]
pub struct Error(pub String);

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Error {}

fn zeroed() -> Box<ZStream> {
    // SAFETY: z_stream is plain data; zalloc/zfree/opaque = NULL selects the zlib defaults.
    Box::new(unsafe { MaybeUninit::<ZStream>::zeroed().assume_init() })
}

/// Deflate with exactly these parameters. Input may be fed in pieces of any size: with
/// `Z_NO_FLUSH` zlib's output does not depend on how the input is split.
pub struct Deflater {
    s: Box<ZStream>,
    buf: Vec<u8>,
}

// The stream state is only touched through &mut self.
unsafe impl Send for Deflater {}

impl Deflater {
    pub fn new(p: Params) -> Result<Deflater, Error> {
        if !p.valid() {
            return Err(Error(format!("invalid zlib parameters {p:?}")));
        }
        let mut s = zeroed();
        // SAFETY: valid stream struct, version string and size as zlib expects.
        let r = unsafe {
            z_deflateInit2_(
                &mut *s,
                p.level,
                Z_DEFLATED,
                p.wbits,
                p.memlevel,
                p.strategy,
                VERSION.as_ptr().cast(),
                size_of::<ZStream>() as c_int,
            )
        };
        if r != Z_OK {
            return Err(Error(format!("deflateInit2 failed ({r})")));
        }
        Ok(Deflater { s, buf: vec![0u8; 1 << 16] })
    }

    fn run(&mut self, mut input: &[u8], flush: c_int, out: &mut dyn FnMut(&[u8]) -> bool) -> Result<bool, Error> {
        loop {
            let take = input.len().min(c_uint::MAX as usize);
            self.s.next_in = input.as_ptr();
            self.s.avail_in = take as c_uint;
            let last = take == input.len();
            let f = if last { flush } else { Z_NO_FLUSH };
            loop {
                self.s.next_out = self.buf.as_mut_ptr();
                self.s.avail_out = self.buf.len() as c_uint;
                // SAFETY: pointers are valid for the given lengths for the duration of the call.
                let r = unsafe { z_deflate(&mut *self.s, f) };
                let produced = self.buf.len() - self.s.avail_out as usize;
                if produced > 0 && !out(&self.buf[..produced]) {
                    return Ok(false);
                }
                match r {
                    Z_STREAM_END => return Ok(true),
                    Z_OK | Z_BUF_ERROR => {}
                    e => return Err(Error(format!("deflate failed ({e})"))),
                }
                if self.s.avail_out != 0 && self.s.avail_in == 0 {
                    break;
                }
            }
            input = &input[take..];
            if last {
                return Ok(true);
            }
        }
    }

    /// Feeds input; `out` gets the produced bytes and returns `false` to stop early.
    pub fn push(&mut self, input: &[u8], out: &mut dyn FnMut(&[u8]) -> bool) -> Result<bool, Error> {
        self.run(input, Z_NO_FLUSH, out)
    }

    /// Ends the stream.
    pub fn finish(mut self, out: &mut dyn FnMut(&[u8]) -> bool) -> Result<bool, Error> {
        self.run(&[], Z_FINISH, out)
    }
}

impl Drop for Deflater {
    fn drop(&mut self) {
        // SAFETY: the stream was initialized in `new`.
        unsafe { z_deflateEnd(&mut *self.s) };
    }
}

/// Deflates `data` completely.
pub fn deflate(data: &[u8], p: Params) -> Result<Vec<u8>, Error> {
    let mut out = Vec::with_capacity(data.len() / 2 + 64);
    let mut d = Deflater::new(p)?;
    d.push(data, &mut |b| {
        out.extend_from_slice(b);
        true
    })?;
    d.finish(&mut |b| {
        out.extend_from_slice(b);
        true
    })?;
    Ok(out)
}

/// `true` if deflating `data` with `p` gives exactly `expected`. Stops at the first difference.
pub fn reproduces(data: &[u8], p: Params, expected: &[u8]) -> bool {
    let Ok(mut d) = Deflater::new(p) else { return false };
    let mut pos = 0usize;
    let mut cmp = |b: &[u8]| {
        let ok = expected.get(pos..pos + b.len()) == Some(b);
        pos += b.len();
        ok
    };
    matches!(d.push(data, &mut cmp), Ok(true)) && matches!(d.finish(&mut cmp), Ok(true)) && pos == expected.len()
}

/// Result of [`inflate`].
#[derive(Debug)]
pub struct Inflated {
    pub data: Vec<u8>,
    /// Bytes of the input that belong to the stream.
    pub consumed: usize,
}

/// Inflates one complete stream at the start of `input`. `None` if it is not a valid complete
/// stream or would inflate to more than `limit` bytes.
pub fn inflate(input: &[u8], wbits: i32, limit: usize) -> Option<Inflated> {
    let mut s = zeroed();
    // SAFETY: as in Deflater::new.
    if unsafe { z_inflateInit2_(&mut *s, wbits, VERSION.as_ptr().cast(), size_of::<ZStream>() as c_int) } != Z_OK {
        return None;
    }
    let mut data: Vec<u8> = Vec::new();
    let take = input.len().min(c_uint::MAX as usize);
    s.next_in = input.as_ptr();
    s.avail_in = take as c_uint;
    let result = loop {
        if data.len() == data.capacity() {
            if data.len() >= limit {
                break None;
            }
            data.reserve((data.len().max(1 << 16)).min(limit - data.len() + 1));
        }
        let spare = (data.capacity() - data.len()).min(c_uint::MAX as usize);
        // SAFETY: writing into the spare capacity of `data`.
        s.next_out = unsafe { data.as_mut_ptr().add(data.len()) };
        s.avail_out = spare as c_uint;
        let r = unsafe { z_inflate(&mut *s, Z_NO_FLUSH) };
        let produced = spare - s.avail_out as usize;
        // SAFETY: zlib initialized `produced` bytes.
        unsafe { data.set_len(data.len() + produced) };
        match r {
            Z_STREAM_END => break (data.len() <= limit).then_some(()),
            Z_OK => {}
            Z_BUF_ERROR if s.avail_in > 0 || produced > 0 => {}
            _ => break None,
        }
    };
    let consumed = take - s.avail_in as usize;
    // SAFETY: initialized above.
    unsafe { z_inflateEnd(&mut *s) };
    result.map(|_| Inflated { data, consumed })
}

/// Version string of the compiled zlib, as a self-check.
pub fn version() -> String {
    // SAFETY: zlibVersion returns a static NUL-terminated string.
    unsafe { std::ffi::CStr::from_ptr(z_zlibVersion()) }.to_string_lossy().into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Vec<u8> {
        (0..200_000u32).flat_map(|i| format!("Zeile {} {}\n", i, i % 97).into_bytes()).collect()
    }

    #[test]
    fn version_is_bundled() {
        assert_eq!(version(), "1.3.1");
    }

    #[test]
    fn round_trip_and_split_input() {
        let data = sample();
        for (wbits, level) in [(15, 6), (-15, 9), (15, 1), (31, 6), (-9, 4)] {
            let p = Params { wbits, level, memlevel: 8, strategy: 0 };
            let z = deflate(&data, p).unwrap();
            assert!(reproduces(&data, p, &z));
            // Fed in odd pieces: same bytes.
            let mut d = Deflater::new(p).unwrap();
            let mut out = Vec::new();
            for piece in data.chunks(7777) {
                d.push(piece, &mut |b| {
                    out.extend_from_slice(b);
                    true
                })
                .unwrap();
            }
            d.finish(&mut |b| {
                out.extend_from_slice(b);
                true
            })
            .unwrap();
            assert_eq!(out, z);
            let mut with_tail = z.clone();
            with_tail.extend_from_slice(b"endstream");
            let i = inflate(&with_tail, wbits, 1 << 30).unwrap();
            assert_eq!(i.data, data);
            assert_eq!(i.consumed, z.len());
            assert!(!reproduces(&data, Params { level: if level == 9 { 8 } else { 9 }, ..p }, &z));
        }
    }

    #[test]
    fn inflate_limits_and_rejects() {
        let z = deflate(&vec![0u8; 10 << 20], Params { wbits: 15, level: 9, memlevel: 8, strategy: 0 }).unwrap();
        assert!(inflate(&z, 15, 1 << 20).is_none());
        assert!(inflate(&z[..z.len() / 2], 15, 1 << 30).is_none());
        assert!(inflate(b"not deflate", 15, 1 << 30).is_none());
        assert!(!Params { wbits: -8, level: 6, memlevel: 8, strategy: 0 }.valid());
    }
}
