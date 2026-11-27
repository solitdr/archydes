//! Recovery data for Archydes archives (SPEC A9): Reed-Solomon parity over the bytes of the
//! archive, so damaged regions can be rebuilt.
//!
//! The covered range `[start, end)` is cut into slices of 64 KiB (the last one padded with
//! zeros). Slices are spread over groups by interleaving: slice `i` belongs to group `i mod G`.
//! A contiguous burst of damage therefore touches every group a little instead of one group a
//! lot, and each group holds its own parity slices (Leopard RS over GF(2^16)).
//!
//! Payload of a RECOVERY segment:
//!
//! ```text
//! [u32 H][head: H bytes CBOR][u32 crc32c(head)]
//! parity slices, group by group                 Σr × 64 KiB
//! [table][u32 crc32c(table)]                    table = BLAKE3-128 of every data slice
//! [table][u32 crc32c(table)]                            then of every parity slice
//! [head][u32 crc32c(head)][u32 H]
//! ```
//!
//! Everything here is open (MIT OR Apache-2.0): creating recovery data needs no knowledge of how
//! the packer decides anything.

use std::fs::File;
use std::io::{BufWriter, Write};

use archydes_format::cbor::{self, Value};
use archydes_format::consts::{FOOTER_LEN, FORMAT_MAJOR, HEADER_LEN, SEGMENT_HEADER_LEN, flags};
use archydes_format::{
    Error, Footer, Header, Index, ReadAt, Result, SegmentHeader, WalkItem, consts::segment_type, corrupt, hash128,
};

/// Size of one slice.
pub const SLICE: usize = 64 << 10;
/// Most data slices in one group (64 MiB of memory per group while encoding).
pub const MAX_GROUP: u64 = 1024;
pub const ALGORITHM: &str = "rs-leopard-gf16";
/// Largest head a reader accepts.
const MAX_HEAD: u32 = 1 << 20;
/// Largest hash table a reader accepts (covers about 4 TiB).
const MAX_TABLE: u64 = 1 << 30;

/// Which bytes are covered and how they are grouped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Layout {
    pub start: u64,
    /// Offset of the RECOVERY segment itself.
    pub end: u64,
    /// `(data slices, parity slices)` per group.
    pub groups: Vec<(u32, u32)>,
    /// Offset of the RECOVERY segment of the previous generation, 0 = none.
    pub prev: u64,
}

impl Layout {
    /// Layout for `[start, end)` with `permille` parity (50 = 5 %), at least one parity slice
    /// per group.
    pub fn new(start: u64, end: u64, permille: u32, prev: u64) -> Layout {
        let n = (end - start).div_ceil(SLICE as u64).max(1);
        let g = n.div_ceil(MAX_GROUP);
        let groups = (0..g)
            .map(|i| {
                let ng = (n - i).div_ceil(g);
                let r = (ng * permille as u64).div_ceil(1000).max(1);
                (ng as u32, r as u32)
            })
            .collect();
        Layout { start, end, groups, prev }
    }

    pub fn data_slices(&self) -> u64 {
        (self.end - self.start).div_ceil(SLICE as u64).max(1)
    }

    pub fn parity_slices(&self) -> u64 {
        self.groups.iter().map(|g| g.1 as u64).sum()
    }

    fn group_count(&self) -> u64 {
        self.groups.len() as u64
    }

    /// Slice numbers of group `g`, in the order they enter the code.
    pub fn group_members(&self, g: usize) -> impl Iterator<Item = u64> + use<> {
        (g as u64..self.data_slices()).step_by(self.groups.len())
    }

    pub fn group_of(&self, slice: u64) -> usize {
        (slice % self.group_count()) as usize
    }

    /// Byte range of a data slice within the archive.
    pub fn slice_range(&self, slice: u64) -> (u64, u64) {
        let a = self.start + slice * SLICE as u64;
        (a, (a + SLICE as u64).min(self.end))
    }

    fn head(&self) -> Vec<u8> {
        let groups = self.groups.iter().map(|&(n, r)| Value::Array(vec![Value::Uint(n as u64), Value::Uint(r as u64)]));
        cbor::encode(&Value::map([
            ("v", Value::Uint(1)),
            ("alg", Value::text(ALGORITHM)),
            ("slice", Value::Uint(SLICE as u64)),
            ("start", Value::Uint(self.start)),
            ("end", Value::Uint(self.end)),
            ("groups", Value::Array(groups.collect())),
            ("prev", Value::Uint(self.prev)),
        ]))
    }

    fn parse_head(bytes: &[u8]) -> Result<Layout> {
        let v = cbor::decode(bytes)?;
        let uint = |k: &str| v.get(k).and_then(Value::as_u64).ok_or_else(|| corrupt(format!("recovery head: {k}")));
        if uint("v")? != 1 {
            return Err(Error::Unsupported("recovery data version".into()));
        }
        if v.get("alg").and_then(Value::as_text) != Some(ALGORITHM) {
            return Err(Error::Unsupported("recovery algorithm".into()));
        }
        if uint("slice")? != SLICE as u64 {
            return Err(Error::Unsupported("recovery slice size".into()));
        }
        let (start, end, prev) = (uint("start")?, uint("end")?, uint("prev")?);
        if start >= end || end > 1 << 56 {
            return Err(corrupt("recovery head: range"));
        }
        let list = v.get("groups").and_then(Value::as_array).ok_or_else(|| corrupt("recovery head: groups"))?;
        let mut groups = Vec::with_capacity(list.len());
        for item in list {
            let pair = item.as_array().filter(|a| a.len() == 2).ok_or_else(|| corrupt("recovery head: group"))?;
            let n = pair[0].as_u64().ok_or_else(|| corrupt("recovery head: group"))?;
            let r = pair[1].as_u64().ok_or_else(|| corrupt("recovery head: group"))?;
            if n == 0 || r == 0 || !reed_solomon_simd::ReedSolomonEncoder::supports(n as usize, r as usize) {
                return Err(corrupt("recovery head: group size"));
            }
            groups.push((n as u32, r as u32));
        }
        let layout = Layout { start, end, groups, prev };
        // The groups must be exactly the interleaving of the covered slices.
        let total = layout.data_slices();
        let g = layout.group_count();
        if g == 0 || g > total {
            return Err(corrupt("recovery head: group count"));
        }
        for (i, &(n, _)) in layout.groups.iter().enumerate() {
            if n as u64 != (total - i as u64).div_ceil(g) {
                return Err(corrupt("recovery head: groups do not match the covered range"));
            }
        }
        if layout.table_len() > MAX_TABLE {
            return Err(Error::Limit("recovery table too large".into()));
        }
        Ok(layout)
    }

    fn table_len(&self) -> u64 {
        (self.data_slices() + self.parity_slices()) * 16
    }

    fn front_len(&self) -> u64 {
        8 + self.head().len() as u64
    }

    /// Payload length of the RECOVERY segment.
    pub fn payload_len(&self) -> u64 {
        let h = self.head().len() as u64;
        (8 + h) + self.parity_slices() * SLICE as u64 + 2 * (self.table_len() + 4) + (h + 8)
    }

    /// Offset of parity slice `k` of group `g` within the payload.
    fn parity_at(&self, g: usize, k: u32) -> u64 {
        let before: u64 = self.groups[..g].iter().map(|x| x.1 as u64).sum();
        self.front_len() + (before + k as u64) * SLICE as u64
    }

    /// Table entry of the first parity slice of group `g`.
    fn parity_entry(&self, g: usize) -> u64 {
        self.data_slices() + self.groups[..g].iter().map(|x| x.1 as u64).sum::<u64>()
    }

    fn table_at(&self, copy: u64) -> u64 {
        self.front_len() + self.parity_slices() * SLICE as u64 + copy * (self.table_len() + 4)
    }
}

/// Reads data slice `i`, zero-padded to a full slice.
fn read_slice<R: ReadAt + ?Sized>(src: &R, layout: &Layout, i: u64, buf: &mut [u8]) -> std::io::Result<()> {
    let (a, b) = layout.slice_range(i);
    let len = (b - a) as usize;
    buf[len..].fill(0);
    src.read_exact_at(&mut buf[..len], a)
}

// ---------------------------------------------------------------------------------------------
// Creating

/// Writes the payload of a RECOVERY segment for `layout`, reading the covered bytes from `src`.
/// `threads` groups are encoded at a time; `progress(done, total)` gets slice counts and returns
/// `false` to cancel.
pub fn write_payload<R: ReadAt + ?Sized>(
    src: &R,
    layout: &Layout,
    threads: usize,
    out: &mut dyn Write,
    progress: &mut dyn FnMut(u64, u64) -> bool,
) -> Result<()> {
    let head = layout.head();
    let head_crc = crc32c::crc32c(&head);
    out.write_all(&(head.len() as u32).to_le_bytes())?;
    out.write_all(&head)?;
    out.write_all(&head_crc.to_le_bytes())?;

    let total = layout.data_slices();
    let mut data_hashes = vec![[0u8; 16]; total as usize];
    let mut parity_hashes = Vec::with_capacity(layout.parity_slices() as usize);
    let mut done = 0u64;
    let batch = threads.clamp(1, 4);
    for first in (0..layout.groups.len()).step_by(batch) {
        let last = (first + batch).min(layout.groups.len());
        let results: Vec<Result<GroupResult>> = std::thread::scope(|s| {
            let jobs: Vec<_> = (first..last).map(|g| s.spawn(move || encode_group(src, layout, g))).collect();
            jobs.into_iter().map(|j| j.join().unwrap_or_else(|_| Err(corrupt("recovery thread panicked")))).collect()
        });
        for r in results {
            let (hashes, parity) = r?;
            done += hashes.len() as u64;
            for (i, h) in hashes {
                data_hashes[i as usize] = h;
            }
            for p in parity {
                parity_hashes.push(hash128(&p));
                out.write_all(&p)?;
            }
        }
        if !progress(done, total) {
            return Err(Error::Cancelled);
        }
    }

    let mut table = Vec::with_capacity(layout.table_len() as usize);
    for h in data_hashes.iter().chain(&parity_hashes) {
        table.extend_from_slice(h);
    }
    let table_crc = crc32c::crc32c(&table).to_le_bytes();
    for _ in 0..2 {
        out.write_all(&table)?;
        out.write_all(&table_crc)?;
    }
    out.write_all(&head)?;
    out.write_all(&head_crc.to_le_bytes())?;
    out.write_all(&(head.len() as u32).to_le_bytes())?;
    Ok(())
}

/// Hashes of the data slices of a group, and its parity slices.
type GroupResult = (Vec<(u64, [u8; 16])>, Vec<Vec<u8>>);
/// Damaged data slices, and damaged parity slices as (group, k).
type CheckResult = (Vec<u64>, Vec<(usize, u32)>);

fn encode_group<R: ReadAt + ?Sized>(src: &R, layout: &Layout, g: usize) -> Result<GroupResult> {
    let (n, r) = layout.groups[g];
    let mut enc = reed_solomon_simd::ReedSolomonEncoder::new(n as usize, r as usize, SLICE).map_err(rs_error)?;
    let mut buf = vec![0u8; SLICE];
    let mut hashes = Vec::with_capacity(n as usize);
    for i in layout.group_members(g) {
        read_slice(src, layout, i, &mut buf)?;
        hashes.push((i, hash128(&buf)));
        enc.add_original_shard(&buf).map_err(rs_error)?;
    }
    let result = enc.encode().map_err(rs_error)?;
    let parity = result.recovery_iter().map(|p| p.to_vec()).collect();
    Ok((hashes, parity))
}

fn rs_error(e: reed_solomon_simd::Error) -> Error {
    corrupt(format!("Reed-Solomon: {e}"))
}

/// Writes a complete RECOVERY segment at `offset` of `file` (the covered data must already be
/// there) and returns its header.
pub fn write_segment(file: &File, layout: &Layout, threads: usize) -> Result<SegmentHeader> {
    let mut w = BufWriter::with_capacity(4 << 20, file);
    std::io::Seek::seek(&mut w, std::io::SeekFrom::Start(layout.end))?;
    let sh = archydes_format::write_segment_streamed(
        &mut w,
        layout.end,
        segment_type::RECOVERY,
        0,
        layout.payload_len(),
        |out| write_payload(file, layout, threads, out, &mut |_, _| true),
    )?;
    w.flush()?;
    Ok(sh)
}

// ---------------------------------------------------------------------------------------------
// Finding and checking

fn read_u32<R: ReadAt + ?Sized>(src: &R, off: u64) -> Result<u32> {
    let mut b = [0u8; 4];
    src.read_exact_at(&mut b, off)?;
    Ok(u32::from_le_bytes(b))
}

/// Front head at the start of a payload.
fn front_head<R: ReadAt + ?Sized>(src: &R, payload: u64) -> Result<Layout> {
    let h = read_u32(src, payload)?;
    if h == 0 || h > MAX_HEAD {
        return Err(corrupt("recovery head length"));
    }
    let mut b = vec![0u8; h as usize];
    src.read_exact_at(&mut b, payload + 4)?;
    if read_u32(src, payload + 4 + h as u64)? != crc32c::crc32c(&b) {
        return Err(corrupt("recovery head checksum"));
    }
    Layout::parse_head(&b)
}

/// Tail head ending at `end`.
fn tail_head<R: ReadAt + ?Sized>(src: &R, end: u64) -> Result<Layout> {
    let h = read_u32(src, end.checked_sub(4).ok_or_else(|| corrupt("short"))?)?;
    if h == 0 || h > MAX_HEAD || (h as u64 + 8) > end {
        return Err(corrupt("recovery head length"));
    }
    let start = end - 8 - h as u64;
    let mut b = vec![0u8; h as usize];
    src.read_exact_at(&mut b, start)?;
    if read_u32(src, end - 8)? != crc32c::crc32c(&b) {
        return Err(corrupt("recovery head checksum"));
    }
    Layout::parse_head(&b)
}

/// All RECOVERY segments, newest first: the one [`locate`] finds, then the older ones through
/// `prev` (SPEC A9). Each older one is found by its front head or, if that is damaged, by its
/// tail head, which ends exactly where the newer range starts. The chain stops at the first
/// segment that can not be read; the ranges it covers are contiguous and disjoint.
pub fn chain<R: ReadAt + ?Sized>(src: &R) -> Vec<Layout> {
    let Some(newest) = locate(src) else { return Vec::new() };
    let mut out = vec![newest];
    loop {
        let l = out.last().unwrap();
        if l.prev == 0 {
            break;
        }
        let (prev, start) = (l.prev, l.start);
        let ok = |p: &Layout| p.end == prev && p.end + SEGMENT_HEADER_LEN as u64 + p.payload_len() == start;
        let found = front_head(src, prev + SEGMENT_HEADER_LEN as u64)
            .ok()
            .filter(ok)
            .or_else(|| tail_head(src, start).ok().filter(ok));
        match found {
            // Strictly older, so the loop ends.
            Some(p) if p.end < l.end && p.start < l.start => out.push(p),
            _ => break,
        }
    }
    out
}

/// The RECOVERY segment that protects the end of the archive, found without trusting the footer
/// or the segment header: by the footer if it is intact, else by the head at the end of the
/// payload, else by searching backwards for the segment.
pub fn locate<R: ReadAt + ?Sized>(src: &R) -> Option<Layout> {
    let size = src.size().ok()?;
    let fits = |l: &Layout| l.end + SEGMENT_HEADER_LEN as u64 + l.payload_len() <= size;
    // 1. Footer.
    if size >= (HEADER_LEN + FOOTER_LEN) as u64 {
        let mut b = [0u8; FOOTER_LEN];
        if src.read_exact_at(&mut b, size - FOOTER_LEN as u64).is_ok()
            && let Ok(f) = Footer::decode(&b)
            && f.recovery_offset != 0
            && let Ok(l) = front_head(src, f.recovery_offset + SEGMENT_HEADER_LEN as u64)
            && l.end == f.recovery_offset
            && fits(&l)
        {
            return Some(l);
        }
    }
    // 2. Tail head, before a footer or at the very end.
    for end in [size.saturating_sub(FOOTER_LEN as u64), size] {
        if let Ok(l) = tail_head(src, end)
            && l.end + SEGMENT_HEADER_LEN as u64 + l.payload_len() == end
        {
            return Some(l);
        }
    }
    // 3. Search backwards for a segment header of type RECOVERY.
    const WINDOW: u64 = 1 << 20;
    let mut end = size;
    while end > HEADER_LEN as u64 {
        let start = end.saturating_sub(WINDOW).max(HEADER_LEN as u64);
        let read_end = (end + SEGMENT_HEADER_LEN as u64).min(size);
        let mut buf = vec![0u8; (read_end - start) as usize];
        src.read_exact_at(&mut buf, start).ok()?;
        for pos in (0..(end - start) as usize).rev() {
            if buf[pos..].starts_with(b"AHSG")
                && let Ok(sh) = SegmentHeader::decode(&buf[pos..])
                && sh.kind == segment_type::RECOVERY
            {
                let off = start + pos as u64;
                let payload = off + SEGMENT_HEADER_LEN as u64;
                let found = front_head(src, payload).or_else(|_| tail_head(src, payload + sh.payload_len));
                if let Ok(l) = found
                    && l.end == off
                    && fits(&l)
                {
                    return Some(l);
                }
            }
        }
        end = start;
    }
    None
}

/// The two copies of the hash table. An entry is trusted if it comes from a copy with a valid
/// checksum, or, if both copies are damaged, if the slice matches either copy.
struct Table {
    copies: [Vec<u8>; 2],
    valid: [bool; 2],
}

impl Table {
    fn read<R: ReadAt + ?Sized>(src: &R, layout: &Layout) -> Result<Table> {
        let payload = layout.end + SEGMENT_HEADER_LEN as u64;
        let len = layout.table_len() as usize;
        let mut copies = [vec![0u8; len], vec![0u8; len]];
        let mut valid = [false; 2];
        for c in 0..2 {
            let at = payload + layout.table_at(c as u64);
            if src.read_exact_at(&mut copies[c], at).is_ok() {
                valid[c] = read_u32(src, at + len as u64).is_ok_and(|crc| crc == crc32c::crc32c(&copies[c]));
            }
        }
        Ok(Table { copies, valid })
    }

    fn damaged(&self) -> bool {
        !(self.valid[0] && self.valid[1])
    }

    fn matches(&self, entry: u64, hash: &[u8; 16]) -> bool {
        let at = entry as usize * 16;
        let of = |c: usize| self.copies[c][at..at + 16] == hash[..];
        match self.valid {
            [true, _] => of(0),
            [false, true] => of(1),
            [false, false] => of(0) || of(1),
        }
    }
}

/// State of the recovery data and of the bytes it covers.
#[derive(Debug, Clone)]
pub struct Status {
    pub layout: Layout,
    /// Data slices whose hash does not match, in ascending order.
    pub damaged_data: Vec<u64>,
    /// Damaged parity slices per group.
    pub damaged_parity: Vec<u32>,
    /// Groups with more damage than parity.
    pub unrepairable_groups: Vec<usize>,
    /// Head, table copies or segment header damaged (rebuilt by `repair`).
    pub recovery_damaged: bool,
}

impl Status {
    pub fn is_clean(&self) -> bool {
        self.damaged_data.is_empty() && !self.recovery_damaged && self.damaged_parity.iter().all(|&d| d == 0)
    }

    /// All damaged data can be rebuilt.
    pub fn repairable(&self) -> bool {
        self.unrepairable_groups.is_empty()
    }

    /// Bytes in damaged data slices.
    pub fn damaged_bytes(&self) -> u64 {
        self.damaged_data.iter().map(|&i| self.layout.slice_range(i)).map(|(a, b)| b - a).sum()
    }

    /// Parity in percent of the covered bytes.
    pub fn percent(&self) -> f64 {
        self.layout.parity_slices() as f64 * 100.0 / self.layout.data_slices() as f64
    }
}

/// Checks every data and parity slice against the hash table.
pub fn check<R: ReadAt + ?Sized>(src: &R, layout: &Layout, threads: usize) -> Result<Status> {
    let table = Table::read(src, layout)?;
    let payload = layout.end + SEGMENT_HEADER_LEN as u64;
    let mut recovery_damaged = table.damaged()
        || front_head(src, payload).ok().as_ref() != Some(layout)
        || tail_head(src, payload + layout.payload_len()).ok().as_ref() != Some(layout);
    let mut hb = [0u8; SEGMENT_HEADER_LEN];
    let header_ok = src.read_exact_at(&mut hb, layout.end).is_ok()
        && SegmentHeader::decode(&hb)
            .is_ok_and(|sh| sh.kind == segment_type::RECOVERY && sh.payload_len == layout.payload_len());
    recovery_damaged |= !header_ok;

    let groups = layout.groups.len();
    let threads = threads.max(1);
    let per_thread: Vec<CheckResult> = std::thread::scope(|s| {
        let table = &table;
        let jobs: Vec<_> = (0..threads)
            .map(|t| {
                s.spawn(move || {
                    let mut buf = vec![0u8; SLICE];
                    let mut bad_data = Vec::new();
                    let mut bad_parity = Vec::new();
                    for g in (t..groups).step_by(threads) {
                        for i in layout.group_members(g) {
                            let ok = read_slice(src, layout, i, &mut buf).is_ok() && table.matches(i, &hash128(&buf));
                            if !ok {
                                bad_data.push(i);
                            }
                        }
                        let entry0 = layout.parity_entry(g);
                        let at0 = payload + layout.parity_at(g, 0);
                        for k in 0..layout.groups[g].1 {
                            let ok = src.read_exact_at(&mut buf, at0 + k as u64 * SLICE as u64).is_ok()
                                && table.matches(entry0 + k as u64, &hash128(&buf));
                            if !ok {
                                bad_parity.push((g, k));
                            }
                        }
                    }
                    (bad_data, bad_parity)
                })
            })
            .collect();
        jobs.into_iter().map(|j| j.join().expect("check thread")).collect()
    });
    let mut damaged_data = Vec::new();
    let mut damaged_parity = vec![0u32; groups];
    for (d, p) in per_thread {
        damaged_data.extend(d);
        for (g, _) in p {
            damaged_parity[g] += 1;
        }
    }
    damaged_data.sort_unstable();
    let mut data_per_group = vec![0u32; groups];
    for &i in &damaged_data {
        data_per_group[layout.group_of(i)] += 1;
    }
    let unrepairable_groups = (0..groups)
        .filter(|&g| data_per_group[g] > 0 && data_per_group[g] + damaged_parity[g] > layout.groups[g].1)
        .collect();
    Ok(Status { layout: layout.clone(), damaged_data, damaged_parity, unrepairable_groups, recovery_damaged })
}

// ---------------------------------------------------------------------------------------------
// Repairing

#[derive(Debug, Default, Clone)]
pub struct RepairReport {
    /// Damaged data slices found and rebuilt.
    pub damaged_slices: u64,
    pub repaired_slices: u64,
    /// Byte ranges that could not be rebuilt.
    pub unrepaired: Vec<(u64, u64)>,
    pub recovery_rewritten: bool,
    pub footer_rewritten: bool,
    pub notes: Vec<String>,
}

impl RepairReport {
    pub fn complete(&self) -> bool {
        self.unrepaired.is_empty()
    }
}

/// Repairs `file` in place: rebuilds damaged slices, then the recovery data itself if it was
/// damaged and everything it covers is intact again, then the footer if it is unusable.
pub fn repair(file: &File, threads: usize) -> Result<RepairReport> {
    let layouts = chain(file);
    let newest = layouts.first().cloned().ok_or_else(|| corrupt("no recovery data found"))?;
    let mut report = RepairReport::default();
    // Newest first: an older RECOVERY segment lies in the range of the newer one and is
    // repaired before it is used.
    for (k, layout) in layouts.iter().enumerate() {
        match repair_range(file, layout, threads, &mut report) {
            Ok(()) => {}
            Err(e) if k > 0 => report.notes.push(format!("older recovery data at {} unusable: {e}", layout.end)),
            Err(e) => return Err(e),
        }
    }

    let footer_at = newest.end + SEGMENT_HEADER_LEN as u64 + newest.payload_len();
    let mut fb = [0u8; FOOTER_LEN];
    let footer_ok = file.read_exact_at(&mut fb, footer_at).is_ok() && Footer::decode(&fb).is_ok();
    if !footer_ok {
        let footer = rebuild_footer(file, &newest)?;
        std::os::unix::fs::FileExt::write_all_at(file, &footer.encode(), footer_at)?;
        file.set_len(footer_at + FOOTER_LEN as u64)?;
        report.footer_rewritten = true;
    }
    file.sync_all()?;
    Ok(report)
}

/// Repairs the range one RECOVERY segment covers, and the segment itself.
fn repair_range(file: &File, layout: &Layout, threads: usize, report: &mut RepairReport) -> Result<()> {
    let layout = layout.clone();
    let status = check(file, &layout, threads)?;
    let table = Table::read(file, &layout)?;
    let payload = layout.end + SEGMENT_HEADER_LEN as u64;
    report.damaged_slices += status.damaged_data.len() as u64;
    let unrepaired_before = report.unrepaired.len();

    let mut per_group: Vec<Vec<u64>> = vec![Vec::new(); layout.groups.len()];
    for &i in &status.damaged_data {
        per_group[layout.group_of(i)].push(i);
    }
    let mut buf = vec![0u8; SLICE];
    for (g, damaged) in per_group.iter().enumerate() {
        if damaged.is_empty() {
            continue;
        }
        let (n, r) = layout.groups[g];
        if status.unrepairable_groups.contains(&g) {
            report.unrepaired.extend(damaged.iter().map(|&i| layout.slice_range(i)));
            continue;
        }
        let members: Vec<u64> = layout.group_members(g).collect();
        let mut originals = Vec::new();
        for (pos, &i) in members.iter().enumerate() {
            if damaged.binary_search(&i).is_err() {
                read_slice(file, &layout, i, &mut buf)?;
                originals.push((pos, buf.clone()));
            }
        }
        let entry0 = layout.parity_entry(g);
        let at0 = payload + layout.parity_at(g, 0);
        let mut parity = Vec::new();
        for k in 0..r {
            if file.read_exact_at(&mut buf, at0 + k as u64 * SLICE as u64).is_ok()
                && table.matches(entry0 + k as u64, &hash128(&buf))
            {
                parity.push((k as usize, buf.clone()));
            }
        }
        let restored = reed_solomon_simd::decode(n as usize, r as usize, originals, parity).map_err(rs_error)?;
        for (pos, data) in restored {
            let i = members[pos];
            if !table.matches(i, &hash128(&data)) {
                report.unrepaired.push(layout.slice_range(i));
                continue;
            }
            let (a, b) = layout.slice_range(i);
            std::os::unix::fs::FileExt::write_all_at(file, &data[..(b - a) as usize], a)?;
            report.repaired_slices += 1;
        }
    }

    let range_complete = report.unrepaired.len() == unrepaired_before;
    if range_complete && !status.is_clean() && (status.recovery_damaged || status.damaged_parity.iter().any(|&d| d > 0))
    {
        write_segment(file, &layout, threads)?;
        report.recovery_rewritten = true;
    } else if !range_complete && status.recovery_damaged {
        report.notes.push("recovery data damaged, kept as it is because data damage remains".into());
    }
    Ok(())
}

/// A footer for the generation that ends with this RECOVERY segment: the last INDEX and
/// INDEX_COPY before it. Encrypted archives are repaired without the password: their index
/// cannot be read, so the generation number continues the previous footer's and the footer
/// points to the last KEY_INFO before the index.
fn rebuild_footer(file: &File, layout: &Layout) -> Result<Footer> {
    let mut hb = [0u8; HEADER_LEN];
    file.read_exact_at(&mut hb, 0)?;
    let header = Header::decode(&hb)?;
    // The walk stops at the first damaged place; then search backwards from the RECOVERY segment.
    let encrypted = header.flags & flags::ENCRYPTED != 0;
    let (mut index, mut copy, mut key_info, mut previous) = (None, None, None, None);
    for item in archydes_format::walk(file) {
        match item {
            WalkItem::Segment { offset, header } if offset < layout.end => match header.kind {
                segment_type::INDEX => index = Some(offset),
                segment_type::INDEX_COPY => copy = Some(offset),
                segment_type::KEY_INFO => key_info = Some(offset),
                _ => {}
            },
            WalkItem::Footer { offset, footer } if offset < layout.end => {
                previous = Some((footer.generation, footer.flags))
            }
            _ => {}
        }
    }
    if index.is_none() && copy.is_none() {
        index = find_backwards(file, layout.end, segment_type::INDEX);
        copy = find_backwards(file, layout.end, segment_type::INDEX_COPY);
        key_info = find_backwards(file, index.or(copy).unwrap_or(layout.end), segment_type::KEY_INFO);
    }
    // Flags as the packer writes them (SPEC A5.1): encrypted from the header (it never
    // changes), recovery data present, several snapshots from the index; without the password
    // that bit comes from the previous footer.
    let footer = |generation: u64, several: bool| Footer {
        major: FORMAT_MAJOR,
        minor: header.minor,
        flags: (header.flags & flags::ENCRYPTED)
            | flags::RECOVERY
            | if several { flags::MULTIPLE_SNAPSHOTS } else { 0 },
        index_offset: index.unwrap_or(0),
        index_copy_offset: copy.unwrap_or(0),
        recovery_offset: layout.end,
        generation,
        key_info_offset: if encrypted { key_info.unwrap_or(0) } else { 0 },
    };
    if encrypted {
        if index.is_none() && copy.is_none() {
            return Err(corrupt("no index for a new footer"));
        }
        let several = previous.is_some_and(|(_, f)| f & flags::MULTIPLE_SNAPSHOTS != 0);
        return Ok(footer(previous.map_or(1, |(g, _)| g + 1), several));
    }
    let read_index = |off: u64| -> Result<Index> {
        let mut hb = [0u8; SEGMENT_HEADER_LEN];
        file.read_exact_at(&mut hb, off)?;
        let sh = SegmentHeader::decode(&hb)?;
        let mut p = vec![0u8; sh.payload_len.min(layout.end - off) as usize];
        file.read_exact_at(&mut p, off + SEGMENT_HEADER_LEN as u64)?;
        if hash128(&p) != sh.payload_hash {
            return Err(corrupt("index hash"));
        }
        Index::decode_payload(&p)
    };
    let index = index
        .and_then(|o| read_index(o).ok())
        .or_else(|| copy.and_then(|o| read_index(o).ok()))
        .ok_or_else(|| corrupt("no readable index for a new footer"))?;
    Ok(footer(index.generation, index.snapshots.len() > 1))
}

/// Last valid segment header of `kind` whose segment ends at or before `end`.
fn find_backwards<R: ReadAt + ?Sized>(src: &R, end: u64, kind: u16) -> Option<u64> {
    const WINDOW: u64 = 1 << 20;
    let mut hi = end;
    while hi > HEADER_LEN as u64 {
        let lo = hi.saturating_sub(WINDOW).max(HEADER_LEN as u64);
        let read_end = (hi + SEGMENT_HEADER_LEN as u64).min(end);
        let mut buf = vec![0u8; (read_end - lo) as usize];
        src.read_exact_at(&mut buf, lo).ok()?;
        for pos in (0..(hi - lo) as usize).rev() {
            if buf[pos..].starts_with(b"AHSG")
                && let Ok(sh) = SegmentHeader::decode(&buf[pos..])
                && sh.kind == kind
                && sh.end(lo + pos as u64).is_some_and(|e| e <= end)
            {
                return Some(lo + pos as u64);
            }
        }
        hi = lo;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn layout_interleaves_and_round_trips() {
        let l = Layout::new(0, 3000 * SLICE as u64 + 5, 50, 0);
        assert_eq!(l.data_slices(), 3001);
        assert_eq!(l.groups.len(), 3);
        assert_eq!(l.groups.iter().map(|g| g.0 as u64).sum::<u64>(), 3001);
        assert_eq!(l.groups[0], (1001, 51));
        assert_eq!(Layout::parse_head(&l.head()).unwrap(), l);
        assert_eq!(l.group_members(1).take(3).collect::<Vec<_>>(), [1, 4, 7]);

        let tiny = Layout::new(0, 100, 50, 0);
        assert_eq!(tiny.groups, [(1, 1)]);
    }

    #[test]
    fn head_rejects_mismatched_groups() {
        let mut l = Layout::new(0, 10 * SLICE as u64, 100, 0);
        l.groups[0].0 += 1;
        assert!(Layout::parse_head(&l.head()).is_err());
    }
}
