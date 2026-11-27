//! Extracting a snapshot (SPEC A12).
//!
//! Order: directories, files (in pack order), hardlinks, symlinks, then directory metadata from
//! the deepest level up. Symlinks come last and every parent directory is checked to be a real
//! directory, so nothing is ever written through a symlink from the archive.

use std::collections::{HashMap, HashSet};
use std::fs::{self, OpenOptions};
use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use archydes_format::{Entry, EntryKind, Error, ReadAt, Result, Snapshot};

use crate::meta;
use crate::path::safe_relative;
use crate::reader::Reader;

#[derive(Debug, Clone)]
pub struct ExtractOptions {
    /// Replace existing files (never directories). Without it, existing paths are skipped.
    pub overwrite: bool,
    /// Keep setuid/setgid bits. Off by default.
    pub keep_setid: bool,
    /// Restore extended attributes.
    pub xattrs: bool,
}

impl Default for ExtractOptions {
    fn default() -> Self {
        ExtractOptions { overwrite: false, keep_setid: false, xattrs: true }
    }
}

#[derive(Debug, Clone)]
pub struct Problem {
    pub path: String,
    pub message: String,
}

#[derive(Debug, Default, Clone)]
pub struct ExtractReport {
    pub files: u64,
    pub directories: u64,
    pub links: u64,
    pub bytes: u64,
    /// Entries that could not be extracted (or only without some metadata).
    pub problems: Vec<Problem>,
}

impl ExtractReport {
    fn problem(&mut self, e: &Entry, message: impl Into<String>) {
        self.problems.push(Problem { path: e.path_nfc.clone(), message: message.into() });
    }
}

pub struct Progress<'a> {
    pub done: u64,
    pub total: u64,
    pub path: &'a str,
}

/// Extracts the entries of `snapshot` that `select` accepts below `dest`, each at its own path.
/// `progress` returns `false` to cancel; then `Error::Cancelled` is returned and the file being
/// written is removed (files already finished stay).
pub fn extract<R: ReadAt>(
    reader: &Reader<R>,
    snapshot: &Snapshot,
    select: &dyn Fn(&Entry) -> bool,
    dest: &Path,
    opts: &ExtractOptions,
    progress: &mut dyn FnMut(&Progress) -> bool,
) -> Result<ExtractReport> {
    let place = |_: usize, e: &Entry| select(e).then(|| e.path.clone());
    extract_mapped(reader, snapshot, &place, dest, opts, progress)
}

/// Like [`extract`], but `place` decides for every entry (by its index in the snapshot) where it
/// goes below `dest` (`/`-separated path bytes), or `None` to leave it out. Every destination is
/// checked like a path from the archive: absolute paths and `..` are refused.
pub fn extract_mapped<R: ReadAt>(
    reader: &Reader<R>,
    snapshot: &Snapshot,
    place: &dyn Fn(usize, &Entry) -> Option<Vec<u8>>,
    dest: &Path,
    opts: &ExtractOptions,
    progress: &mut dyn FnMut(&Progress) -> bool,
) -> Result<ExtractReport> {
    fs::create_dir_all(dest)?;
    let mut report = ExtractReport::default();
    let (mut dirs, mut files, mut hardlinks, mut symlinks) = (vec![], vec![], vec![], vec![]);
    for (i, e) in snapshot.entries.iter().enumerate() {
        let Some(to) = place(i, e) else { continue };
        let Some(rel) = safe_relative(&to) else {
            report.problem(e, "unsafe path (absolute or with ..), skipped");
            continue;
        };
        match e.kind {
            EntryKind::Directory => dirs.push((e, rel)),
            EntryKind::File => files.push((e, rel)),
            EntryKind::Hardlink => hardlinks.push((e, rel)),
            EntryKind::Symlink => symlinks.push((e, rel)),
        }
    }
    let by_path: HashMap<&[u8], &Entry> =
        snapshot.entries.iter().filter(|e| e.kind == EntryKind::File).map(|e| (e.path.as_slice(), e)).collect();
    let total: u64 = files.iter().map(|(e, _)| e.size).sum();
    files.sort_by_key(|(e, _)| reader.first_location(e));

    let mut checked = HashSet::new();
    let mut done = 0u64;

    for (e, rel) in &dirs {
        match ensure_dir(dest, rel, &mut checked) {
            Ok(()) => report.directories += 1,
            Err(err) => report.problem(e, err.to_string()),
        }
    }

    // Packs in the order the files need them; a second thread decodes (decrypts, decompresses)
    // the next ones while files are written.
    let mut sequence: Vec<u32> = Vec::new();
    let mut first_use: HashMap<u32, usize> = HashMap::new();
    for (e, _) in &files {
        for c in reader.chunks_of(e) {
            let pack = reader.archive.index.chunks.pack[c as usize];
            first_use.entry(pack).or_insert_with(|| {
                sequence.push(pack);
                sequence.len() - 1
            });
        }
    }
    let finished = AtomicBool::new(false);
    let next = AtomicUsize::new(0);
    // Original path → where it was written, for hardlinks.
    let mut extracted: HashMap<&[u8], &Path> = HashMap::new();
    std::thread::scope(|scope| -> Result<()> {
        if sequence.len() > 1 {
            let workers = std::thread::available_parallelism().map_or(2, |n| n.get()).clamp(2, 4) - 1;
            let ahead = (workers + 1).min(reader.cache_slots() - 2);
            let shared = (&sequence, &first_use, &next, &finished);
            for _ in 0..workers {
                scope.spawn(move || prefetch(reader, shared.0, shared.1, shared.2, ahead, shared.3));
            }
        }
        let result = (|| {
            for (e, rel) in &files {
                if !progress(&Progress { done, total, path: &e.path_nfc }) {
                    return Err(Error::Cancelled);
                }
                match write_file(reader, e, dest, rel, opts, &mut checked) {
                    Ok(()) => {
                        apply_metadata(reader, e, &dest.join(rel), opts, &mut report);
                        report.files += 1;
                        report.bytes += e.size;
                        extracted.insert(&e.path, rel.as_path());
                    }
                    Err(err) => report.problem(e, err.to_string()),
                }
                done += e.size;
            }
            Ok(())
        })();
        finished.store(true, Ordering::Relaxed);
        result
    })?;

    for (e, rel) in &hardlinks {
        let target = e.target.as_deref().unwrap_or_default();
        let result = match (safe_relative(target), by_path.get(target)) {
            (Some(_), Some(original)) => {
                let full = dest.join(rel);
                prepare(dest, rel, opts.overwrite, &mut checked).and_then(|_| {
                    let linked =
                        extracted.get(target).is_some_and(|written| fs::hard_link(dest.join(written), &full).is_ok());
                    if linked {
                        Ok(())
                    } else {
                        // Original not extracted (not selected) or links not possible: copy.
                        write_file(reader, original, dest, rel, opts, &mut checked)
                            .map(|_| apply_metadata(reader, original, &full, opts, &mut report))
                    }
                })
            }
            _ => Err(archydes_format::corrupt("hardlink to a missing or unsafe original")),
        };
        match result {
            Ok(()) => report.links += 1,
            Err(err) => report.problem(e, err.to_string()),
        }
    }

    for (e, rel) in &symlinks {
        let full = dest.join(rel);
        let result = prepare(dest, rel, opts.overwrite, &mut checked)
            .and_then(|_| meta::symlink(e.target.as_deref().unwrap_or_default(), &full).map_err(Error::Io));
        match result {
            Ok(()) => {
                apply_metadata(reader, e, &full, opts, &mut report);
                report.links += 1;
            }
            Err(err) => report.problem(e, err.to_string()),
        }
    }

    // Directory metadata last (writing into them changes mtime; a read-only mode would block
    // writing), deepest first.
    dirs.sort_by_key(|(_, rel)| std::cmp::Reverse(rel.components().count()));
    for (e, rel) in &dirs {
        apply_metadata(reader, e, &dest.join(rel), opts, &mut report);
    }

    progress(&Progress { done: total, total, path: "" });
    Ok(report)
}

/// Decodes the packs of `sequence` into the reader's cache, at most `ahead` past the one the
/// extraction is reading, so decrypting and decompressing overlap with writing files. Several
/// threads share `next`.
fn prefetch<R: ReadAt>(
    reader: &Reader<R>,
    sequence: &[u32],
    first_use: &HashMap<u32, usize>,
    next: &AtomicUsize,
    ahead: usize,
    finished: &AtomicBool,
) {
    while !finished.load(Ordering::Relaxed) {
        let at = reader.last_requested().and_then(|p| first_use.get(&p).copied()).unwrap_or(0);
        // Packs the extraction already reached are not worth decoding ahead.
        next.fetch_max(at + 1, Ordering::Relaxed);
        let n = next.load(Ordering::Relaxed);
        if n >= sequence.len() {
            return;
        }
        if n > at + ahead {
            std::thread::sleep(Duration::from_millis(1));
            continue;
        }
        if next.compare_exchange(n, n + 1, Ordering::Relaxed, Ordering::Relaxed).is_ok() {
            // Errors show up again when the extraction reads the pack itself.
            let _ = reader.prefetch(sequence[n]);
        }
    }
}

/// Creates the directory `dest/rel` and all parents; each existing component must be a real
/// directory (not a symlink).
fn ensure_dir(dest: &Path, rel: &Path, checked: &mut HashSet<PathBuf>) -> Result<()> {
    let mut cur = dest.to_path_buf();
    for comp in rel.components() {
        cur.push(comp);
        if checked.contains(&cur) {
            continue;
        }
        match fs::symlink_metadata(&cur) {
            Ok(m) if m.is_dir() => {}
            Ok(_) => {
                return Err(Error::Io(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    format!("{} exists and is not a directory", cur.display()),
                )));
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => fs::create_dir(&cur)?,
            Err(e) => return Err(e.into()),
        }
        checked.insert(cur.clone());
    }
    Ok(())
}

/// Parents exist and are directories; an existing non-directory at the path is removed when
/// overwriting, otherwise an error.
fn prepare(dest: &Path, rel: &Path, overwrite: bool, checked: &mut HashSet<PathBuf>) -> Result<()> {
    if let Some(parent) = rel.parent() {
        ensure_dir(dest, parent, checked)?;
    }
    let full = dest.join(rel);
    match fs::symlink_metadata(&full) {
        Ok(m) if overwrite && !m.is_dir() => fs::remove_file(&full)?,
        Ok(_) => {
            return Err(Error::Io(io::Error::new(io::ErrorKind::AlreadyExists, "already exists")));
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }
    Ok(())
}

fn write_file<R: ReadAt>(
    reader: &Reader<R>,
    e: &Entry,
    dest: &Path,
    rel: &Path,
    opts: &ExtractOptions,
    checked: &mut HashSet<PathBuf>,
) -> Result<()> {
    prepare(dest, rel, opts.overwrite, checked)?;
    let full = dest.join(rel);
    let file = OpenOptions::new().write(true).create_new(true).open(&full)?;
    let mut w = BufWriter::with_capacity(1 << 20, file);
    let result = reader.write_file(e, &mut w).and_then(|_| w.flush().map_err(Error::Io));
    drop(w);
    if result.is_err() {
        let _ = fs::remove_file(&full);
    }
    result
}

/// Extended attributes, permissions, times. Failures are reported, not fatal.
fn apply_metadata<R: ReadAt>(
    reader: &Reader<R>,
    e: &Entry,
    full: &Path,
    opts: &ExtractOptions,
    report: &mut ExtractReport,
) {
    if opts.xattrs {
        for (name, stream) in &e.xattrs {
            let result = reader.stream_bytes(stream).and_then(|v| meta::set_xattr(full, name, &v).map_err(Error::Io));
            if let Err(err) = result {
                report.problem(e, format!("extended attribute {name}: {err}"));
            }
        }
    }
    if e.kind != EntryKind::Symlink {
        let mask = if opts.keep_setid { 0o7777 } else { 0o1777 };
        if let Err(err) = meta::set_mode(full, e.mode & mask) {
            report.problem(e, format!("permissions: {err}"));
        }
    }
    if let Err(err) = meta::set_times(full, e.mtime_ns, e.btime_ns) {
        report.problem(e, format!("times: {err}"));
    }
}
