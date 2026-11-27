//! `archydes`: list, extract, verify, repair and inspect Archydes archives.
//!
//! The commands are a library so that other tools can embed them.

use std::fs::File;
use std::io::{IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{Duration, Instant};

use archydes_decode::{ExtractOptions, Reader};
use archydes_format::consts::{codec, flags};
use archydes_format::{Entry, EntryKind, Error, Snapshot};
use clap::{Args, Parser, Subcommand};

#[derive(Parser)]
#[command(name = "archydes", version, about = "List, extract, verify and repair Archydes archives (.archy)")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

/// How an encrypted archive gets its password: `--password-file`, else the environment
/// variable `ARCHYDES_PASSWORD`, else a prompt on the terminal.
#[derive(Args, Clone, Default)]
pub struct PasswordArgs {
    /// Read the password of an encrypted archive from this file (first line)
    #[arg(long, value_name = "FILE")]
    pub password_file: Option<PathBuf>,
}

#[derive(Subcommand)]
pub enum Command {
    /// Show format, generation, sizes and snapshots of an archive
    Info {
        archive: PathBuf,
        #[command(flatten)]
        password: PasswordArgs,
    },
    /// List the entries of a snapshot
    List {
        archive: PathBuf,
        #[command(flatten)]
        password: PasswordArgs,
        /// Snapshot id (default: the newest)
        #[arg(short, long)]
        snapshot: Option<u64>,
        /// Show kind, permissions, size and date
        #[arg(short, long)]
        long: bool,
    },
    /// Extract a snapshot, or the given paths of it
    Extract {
        archive: PathBuf,
        #[command(flatten)]
        password: PasswordArgs,
        /// Paths inside the archive (files or folders); everything if none
        paths: Vec<String>,
        /// Destination folder
        #[arg(short = 'C', long = "directory", default_value = ".")]
        directory: PathBuf,
        /// Snapshot id (default: the newest)
        #[arg(short, long)]
        snapshot: Option<u64>,
        /// Replace existing files
        #[arg(long)]
        overwrite: bool,
        /// Do not restore extended attributes
        #[arg(long)]
        no_xattrs: bool,
        /// Keep setuid/setgid bits
        #[arg(long)]
        keep_setid: bool,
    },
    /// Check every pack, chunk and file, and the recovery data. Without the password of an
    /// encrypted archive only its structure and recovery data are checked
    Verify {
        archive: PathBuf,
        #[command(flatten)]
        password: PasswordArgs,
        /// Check only structure and recovery data, without asking for a password
        #[arg(long)]
        structure: bool,
    },
    /// Rebuild damaged parts with the recovery data. Writes a repaired copy
    /// (<name>-repaired.archy) unless --in-place is given
    Repair {
        archive: PathBuf,
        /// Where to write the repaired copy
        #[arg(short, long, conflicts_with = "in_place")]
        output: Option<PathBuf>,
        /// Repair the archive itself instead of a copy
        #[arg(long)]
        in_place: bool,
    },
}

/// Exit codes: 0 ok, 1 problems found or some entries failed, 2 the command failed.
pub fn run(command: Command) -> ExitCode {
    match execute(command) {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::from(1),
        Err(e) => {
            eprintln!("archydes: {e}");
            ExitCode::from(2)
        }
    }
}

pub fn main() -> ExitCode {
    run(Cli::parse().command)
}

/// `Ok(false)`: finished, but with problems.
pub fn execute(command: Command) -> Result<bool, Error> {
    match command {
        Command::Info { archive, password } => info(&archive, &password),
        Command::List { archive, password, snapshot, long } => list(&archive, &password, snapshot, long),
        Command::Extract { archive, password, paths, directory, snapshot, overwrite, no_xattrs, keep_setid } => {
            let opts = ExtractOptions { overwrite, keep_setid, xattrs: !no_xattrs };
            extract(&archive, &password, &paths, &directory, snapshot, &opts)
        }
        Command::Verify { archive, password, structure } => verify(&archive, &password, structure),
        Command::Repair { archive, output, in_place } => repair(&archive, output, in_place),
    }
}

/// Opens an archive, asking for the password if it is encrypted.
pub fn open(path: &Path, password: &PasswordArgs) -> Result<Reader<File>, Error> {
    let reader = unlock(path, password)?;
    for w in &reader.archive.warnings {
        eprintln!("archydes: warning: {w}");
    }
    if reader.archive.interrupted > 0 {
        eprintln!(
            "archydes: note: {} after the last footer are the remains of an interrupted add; the archive is complete without them and the next add removes them",
            human(reader.archive.interrupted)
        );
    }
    Ok(reader)
}

fn unlock(path: &Path, args: &PasswordArgs) -> Result<Reader<File>, Error> {
    match Reader::open(File::open(path)?) {
        Err(Error::PasswordRequired) => {}
        other => return other,
    }
    if let Some(file) = &args.password_file {
        let text = std::fs::read_to_string(file)?;
        let password = text.lines().next().unwrap_or_default();
        return Reader::open_with(File::open(path)?, Some(password));
    }
    if let Ok(password) = std::env::var("ARCHYDES_PASSWORD") {
        return Reader::open_with(File::open(path)?, Some(&password));
    }
    if !std::io::stdin().is_terminal() {
        return Err(Error::PasswordRequired);
    }
    for attempt in 1..=3 {
        let password = rpassword::prompt_password(format!("Password for {}: ", path.display()))?;
        match Reader::open_with(File::open(path)?, Some(&password)) {
            Err(Error::WrongPassword) if attempt < 3 => eprintln!("archydes: wrong password"),
            other => return other,
        }
    }
    Err(Error::WrongPassword)
}

pub fn pick_snapshot(reader: &Reader<File>, id: Option<u64>) -> Result<&Snapshot, Error> {
    let snaps = &reader.archive.index.snapshots;
    match id {
        Some(id) => snaps.iter().find(|s| s.id == id).ok_or_else(|| Error::Unsupported(format!("no snapshot {id}"))),
        None => snaps.last().ok_or_else(|| Error::Unsupported("the archive has no snapshot".into())),
    }
}

pub fn human(n: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut v = n as f64;
    let mut u = 0;
    while v >= 1000.0 && u < UNITS.len() - 1 {
        v /= 1000.0;
        u += 1;
    }
    if u == 0 { format!("{n} B") } else { format!("{v:.1} {}", UNITS[u]) }
}

/// `YYYY-MM-DD HH:MM` in UTC.
pub fn date(ns: i64) -> String {
    let secs = ns.div_euclid(1_000_000_000);
    let (days, rem) = (secs.div_euclid(86_400), secs.rem_euclid(86_400));
    // Civil date from days since 1970-01-01 (H. Hinnant).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("{y:04}-{m:02}-{d:02} {:02}:{:02}", rem / 3600, rem % 3600 / 60)
}

fn info(path: &Path, password: &PasswordArgs) -> Result<bool, Error> {
    let reader = open(path, password)?;
    let a = &reader.archive;
    let i = &a.index;
    let uuid: String = a.header.uuid.iter().map(|b| format!("{b:02x}")).collect();
    println!("Archive:      {}", path.display());
    println!("Format:       {}.{}", a.footer.major, a.footer.minor);
    println!("UUID:         {uuid}");
    println!("Created:      {} UTC", date(a.header.created_ns));
    println!("Generation:   {}", a.footer.generation);
    let mut f = Vec::new();
    if a.footer.flags & flags::ENCRYPTED != 0 {
        f.push("encrypted");
    }
    if a.footer.flags & flags::RECOVERY != 0 {
        f.push("recovery data");
    }
    if a.footer.flags & flags::MULTIPLE_SNAPSHOTS != 0 {
        f.push("several snapshots");
    }
    println!("Flags:        {}", if f.is_empty() { "none".into() } else { f.join(", ") });
    println!("File size:    {}", human(a.file_size()));
    let ulen: u64 = i.packs.iter().map(|p| p.ulen).sum();
    let clen: u64 = i.packs.iter().map(|p| p.clen).sum();
    println!("Packs:        {} ({} → {})", i.packs.len(), human(ulen), human(clen));
    for id in [codec::NONE, codec::ZSTD, codec::LZMA2] {
        let n = i.packs.iter().filter(|p| p.codec == id).count();
        if n > 0 {
            println!("  {:<11} {n}", codec::name(id));
        }
    }
    println!("Chunks:       {}", i.chunks.len());
    let layouts = if a.footer.recovery_offset != 0 { archydes_recovery::chain(a.source()) } else { Vec::new() };
    if !layouts.is_empty() {
        let parity: u64 = layouts.iter().map(|l| l.parity_slices()).sum();
        let data: u64 = layouts.iter().map(|l| l.data_slices()).sum();
        let covered: u64 = layouts.iter().map(|l| l.end - l.start).sum();
        let groups: usize = layouts.iter().map(|l| l.groups.len()).sum();
        let pct = parity as f64 * 100.0 / data as f64;
        println!("Recovery:     {pct:.1} % over {} in {groups} groups, {} segment(s)", human(covered), layouts.len());
    }
    if let Some(c) = i.cdc {
        println!("Chunking:     FastCDC {} / {} / {}", human(c.min), human(c.avg), human(c.max));
    }
    println!("Snapshots:");
    for s in &i.snapshots {
        let files = s.entries.iter().filter(|e| e.kind == EntryKind::File).count();
        let size: u64 = s.entries.iter().map(|e| e.size).sum();
        let comment = if s.comment.is_empty() { String::new() } else { format!("  „{}“", s.comment) };
        println!("  {:>3}  {} UTC  {files} files, {}{comment}", s.id, date(s.time_ns), human(size));
    }
    Ok(true)
}

fn kind_char(e: &Entry) -> char {
    match e.kind {
        EntryKind::File => '-',
        EntryKind::Directory => 'd',
        EntryKind::Symlink => 'l',
        EntryKind::Hardlink => 'h',
    }
}

fn list(path: &Path, password: &PasswordArgs, snapshot: Option<u64>, long: bool) -> Result<bool, Error> {
    let reader = open(path, password)?;
    let snap = pick_snapshot(&reader, snapshot)?;
    let mut out = std::io::stdout().lock();
    for e in &snap.entries {
        let name = if e.kind == EntryKind::Directory { format!("{}/", e.path_nfc) } else { e.path_nfc.clone() };
        let target = match (&e.kind, &e.target) {
            (EntryKind::Symlink, Some(t)) => format!(" -> {}", String::from_utf8_lossy(t)),
            (EntryKind::Hardlink, Some(t)) => format!(" => {}", String::from_utf8_lossy(t)),
            _ => String::new(),
        };
        let line = if long {
            format!("{}{:04o} {:>12} {}  {name}{target}\n", kind_char(e), e.mode & 0o7777, e.size, date(e.mtime_ns))
        } else {
            format!("{name}{target}\n")
        };
        if out.write_all(line.as_bytes()).is_err() {
            break; // stdout closed (e.g. piped into head)
        }
    }
    Ok(true)
}

/// Progress on stderr, at most 5 times per second, only on a terminal.
pub struct ProgressLine {
    enabled: bool,
    last: Instant,
    started: Instant,
}

impl Default for ProgressLine {
    fn default() -> Self {
        Self::new()
    }
}

impl ProgressLine {
    pub fn new() -> Self {
        ProgressLine {
            enabled: std::io::stderr().is_terminal(),
            last: Instant::now() - Duration::from_secs(1),
            started: Instant::now(),
        }
    }

    pub fn update(&mut self, verb: &str, done: u64, total: u64, path: &str) {
        if !self.enabled || self.last.elapsed() < Duration::from_millis(200) {
            return;
        }
        self.last = Instant::now();
        let pct = (done * 100).checked_div(total).unwrap_or(100);
        let mut p: String = path.chars().rev().take(50).collect::<Vec<_>>().into_iter().rev().collect();
        if p.len() < path.len() {
            p = format!("…{p}");
        }
        eprint!("\r\x1b[2K{verb} {pct:>3} %  {} / {}  {p}", human(done), human(total));
    }

    pub fn finish(&self) {
        if self.enabled {
            eprint!("\r\x1b[2K");
        }
    }

    pub fn elapsed(&self) -> Duration {
        self.started.elapsed()
    }
}

fn extract(
    path: &Path,
    password: &PasswordArgs,
    paths: &[String],
    dest: &Path,
    snapshot: Option<u64>,
    opts: &ExtractOptions,
) -> Result<bool, Error> {
    let reader = open(path, password)?;
    let snap = pick_snapshot(&reader, snapshot)?;
    let wanted: Vec<String> = paths.iter().map(|p| p.trim_end_matches('/').to_owned()).collect();
    let select = |e: &Entry| {
        wanted.is_empty()
            || wanted
                .iter()
                .any(|w| e.path_nfc == *w || e.path_nfc.strip_prefix(w.as_str()).is_some_and(|r| r.starts_with('/')))
    };
    let mut line = ProgressLine::new();
    let report = archydes_decode::extract(&reader, snap, &select, dest, opts, &mut |p| {
        line.update("Extracting", p.done, p.total, p.path);
        true
    })?;
    line.finish();
    for p in &report.problems {
        eprintln!("archydes: {}: {}", p.path, p.message);
    }
    println!(
        "{} files ({}), {} folders, {} links extracted to {} in {:.1} s",
        report.files,
        human(report.bytes),
        report.directories,
        report.links,
        dest.display(),
        line.elapsed().as_secs_f64()
    );
    Ok(report.problems.is_empty())
}

fn threads() -> usize {
    std::thread::available_parallelism().map_or(4, |n| n.get())
}

/// Prints the state of the recovery data of every generation; `true` if it and the data it
/// covers are intact.
fn recovery_status(file: &File) -> Result<bool, Error> {
    let layouts = archydes_recovery::chain(file);
    if layouts.is_empty() {
        println!("Recovery:     none");
        return Ok(true);
    }
    let mut ok = true;
    for (k, layout) in layouts.iter().enumerate() {
        let label = if layouts.len() == 1 {
            "Recovery:    ".to_string()
        } else {
            format!("Recovery {}/{}:", k + 1, layouts.len())
        };
        let s = archydes_recovery::check(file, layout, threads())?;
        print!(
            "{label} {:.1} % ({} parity slices for {} from {})",
            s.percent(),
            layout.parity_slices(),
            human(layout.end - layout.start),
            human(layout.start)
        );
        if s.is_clean() {
            println!(", intact");
            continue;
        }
        ok = false;
        println!();
        let parity: u32 = s.damaged_parity.iter().sum();
        if !s.damaged_data.is_empty() {
            println!("  {} damaged slices ({})", s.damaged_data.len(), human(s.damaged_bytes()));
        }
        if parity > 0 || s.recovery_damaged {
            println!("  recovery data itself damaged ({parity} parity slices)");
        }
        if s.repairable() {
            println!("  repairable: run `archydes repair`");
        } else {
            println!(
                "  NOT fully repairable: {} of {} groups have more damage than parity; `archydes repair` rebuilds the rest",
                s.unrepairable_groups.len(),
                layout.groups.len()
            );
        }
    }
    Ok(ok)
}

/// Without the password: every segment against its hash, and the recovery data.
fn verify_structure(path: &Path) -> Result<bool, Error> {
    let file = File::open(path)?;
    let report = archydes_decode::verify::verify_structure(&file)?;
    for p in &report.problems {
        println!("problem: {p}");
    }
    let recovery_ok = recovery_status(&file)?;
    if report.is_ok() {
        println!("Structure OK: {} segments; the contents need the password to be checked", report.segments);
    } else {
        println!("DAMAGED: {} problems in the structure", report.problems.len());
    }
    Ok(report.is_ok() && recovery_ok)
}

fn verify(path: &Path, password: &PasswordArgs, structure: bool) -> Result<bool, Error> {
    if structure {
        return verify_structure(path);
    }
    let reader = match open(path, password) {
        Ok(r) => r,
        Err(Error::PasswordRequired) => {
            eprintln!("archydes: encrypted and no password given: checking only structure and recovery data");
            return verify_structure(path);
        }
        Err(e) => {
            if let Ok(f) = File::open(path)
                && archydes_recovery::locate(&f).is_some()
            {
                eprintln!("archydes: {e}");
                eprintln!("archydes: the archive has recovery data: try `archydes repair`");
                return Ok(false);
            }
            return Err(e);
        }
    };
    let mut line = ProgressLine::new();
    let report = archydes_decode::verify(&reader, &mut |done, total| {
        line.update("Verifying", done, total, "");
        true
    })?;
    line.finish();
    for p in &report.problems {
        println!("problem: {p}");
    }
    for f in &report.damaged_files {
        println!("damaged: {} (snapshot {}): {}", f.path, f.snapshot, f.reason);
    }
    let recovery_ok = recovery_status(reader.archive.source())?;
    if report.is_ok() {
        println!(
            "OK: {} segments, {} packs, {} chunks, {} files ({}) checked in {:.1} s",
            report.segments,
            report.packs,
            report.chunks,
            report.files,
            human(report.bytes),
            line.elapsed().as_secs_f64()
        );
    } else {
        println!("DAMAGED: {} files affected, {} files intact", report.damaged_files.len(), report.files);
    }
    Ok(report.is_ok() && recovery_ok)
}

fn repaired_name(path: &Path) -> PathBuf {
    let stem = path.file_stem().map(|s| s.to_string_lossy().into_owned()).unwrap_or_else(|| "archive".into());
    let ext = path.extension().map(|e| e.to_string_lossy().into_owned()).unwrap_or_else(|| "archy".into());
    path.with_file_name(format!("{stem}-repaired.{ext}"))
}

fn repair(path: &Path, output: Option<PathBuf>, in_place: bool) -> Result<bool, Error> {
    let target = if in_place {
        path.to_path_buf()
    } else {
        let out = output.unwrap_or_else(|| repaired_name(path));
        if std::fs::symlink_metadata(&out).is_ok() {
            return Err(Error::Io(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                format!("{} exists", out.display()),
            )));
        }
        std::fs::copy(path, &out)?;
        out
    };
    let file = std::fs::OpenOptions::new().read(true).write(true).open(&target)?;
    let report = match archydes_recovery::repair(&file, threads()) {
        Ok(r) => r,
        Err(e) => {
            if !in_place {
                let _ = std::fs::remove_file(&target);
            }
            return Err(e);
        }
    };
    drop(file);
    if report.damaged_slices == 0 && !report.recovery_rewritten && !report.footer_rewritten {
        println!("No damage found in the range the recovery data covers.");
    } else {
        println!("Damaged slices:   {}", report.damaged_slices);
        println!("Rebuilt:          {}", report.repaired_slices);
        let lost: u64 = report.unrepaired.iter().map(|(a, b)| b - a).sum();
        if !report.unrepaired.is_empty() {
            println!("Not rebuilt:      {} slices ({})", report.unrepaired.len(), human(lost));
        }
        if report.recovery_rewritten {
            println!("Recovery data:    rewritten");
        }
        if report.footer_rewritten {
            println!("Footer:           rewritten");
        }
    }
    for n in &report.notes {
        println!("note: {n}");
    }
    println!("Written to:       {}", target.display());

    // What the repaired archive still lacks, file by file; encrypted ones without the password
    // only as far as the structure goes.
    let reader = match Reader::open(File::open(&target)?) {
        Err(Error::PasswordRequired) => return Ok(verify_structure(&target)? && report.complete()),
        other => other?,
    };
    let v = archydes_decode::verify(&reader, &mut |_, _| true)?;
    for p in &v.problems {
        println!("problem: {p}");
    }
    for f in &v.damaged_files {
        println!("damaged: {} (snapshot {}): {}", f.path, f.snapshot, f.reason);
    }
    if v.is_ok() && report.complete() {
        println!("OK: {} files intact", v.files);
        Ok(true)
    } else {
        println!("PARTLY REPAIRED: {} files damaged, {} files intact", v.damaged_files.len(), v.files);
        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn dates() {
        assert_eq!(super::date(0), "1970-01-01 00:00");
        assert_eq!(super::date(1_764_115_200 * 1_000_000_000), "2025-11-26 00:00");
        assert_eq!(super::date(-1_000_000_000), "1969-12-31 23:59");
    }
}
