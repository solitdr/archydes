//! Restoring metadata: permissions, times, extended attributes, symlinks.

use std::io;
use std::path::Path;

pub(crate) fn split_ns(ns: i64) -> (i64, u32) {
    (ns.div_euclid(1_000_000_000), ns.rem_euclid(1_000_000_000) as u32)
}

#[cfg(unix)]
pub(crate) fn set_mode(path: &Path, mode: u32) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
}

#[cfg(not(unix))]
pub(crate) fn set_mode(path: &Path, mode: u32) -> io::Result<()> {
    // Only the write bit has a meaning here.
    let mut p = std::fs::metadata(path)?.permissions();
    p.set_readonly(mode & 0o200 == 0);
    std::fs::set_permissions(path, p)
}

/// Sets birth time (macOS) and modification time, without following symlinks.
pub(crate) fn set_times(path: &Path, mtime_ns: i64, btime_ns: Option<i64>) -> io::Result<()> {
    if let Some(b) = btime_ns {
        set_btime(path, b)?;
    }
    let t = system_time(mtime_ns);
    std::fs::set_times_nofollow(path, std::fs::FileTimes::new().set_modified(t).set_accessed(t))
}

pub(crate) fn system_time(ns: i64) -> std::time::SystemTime {
    use std::time::{Duration, UNIX_EPOCH};
    if ns >= 0 {
        UNIX_EPOCH + Duration::from_nanos(ns as u64)
    } else {
        UNIX_EPOCH - Duration::from_nanos(ns.unsigned_abs())
    }
}

#[cfg(target_os = "macos")]
fn set_btime(path: &Path, ns: i64) -> io::Result<()> {
    use std::os::unix::ffi::OsStrExt;
    let c = std::ffi::CString::new(path.as_os_str().as_bytes())?;
    let (s, n) = split_ns(ns);
    let mut attrs: libc::attrlist = unsafe { std::mem::zeroed() };
    attrs.bitmapcount = libc::ATTR_BIT_MAP_COUNT;
    attrs.commonattr = libc::ATTR_CMN_CRTIME;
    let mut ts = libc::timespec { tv_sec: s, tv_nsec: n as libc::c_long };
    // SAFETY: attrs and ts are valid for the duration of the call; the size matches ts.
    let r = unsafe {
        libc::setattrlist(
            c.as_ptr(),
            (&mut attrs as *mut libc::attrlist).cast(),
            (&mut ts as *mut libc::timespec).cast(),
            std::mem::size_of::<libc::timespec>(),
            libc::FSOPT_NOFOLLOW,
        )
    };
    if r == 0 { Ok(()) } else { Err(io::Error::last_os_error()) }
}

#[cfg(not(target_os = "macos"))]
fn set_btime(_path: &Path, _ns: i64) -> io::Result<()> {
    Ok(())
}

#[cfg(unix)]
pub(crate) fn set_xattr(path: &Path, name: &str, value: &[u8]) -> io::Result<()> {
    xattr::set(path, name, value)
}

#[cfg(not(unix))]
pub(crate) fn set_xattr(_path: &Path, _name: &str, _value: &[u8]) -> io::Result<()> {
    Err(io::Error::new(io::ErrorKind::Unsupported, "extended attributes are not supported here"))
}

#[cfg(unix)]
pub(crate) fn symlink(target: &[u8], path: &Path) -> io::Result<()> {
    use std::os::unix::ffi::OsStrExt;
    std::os::unix::fs::symlink(std::ffi::OsStr::from_bytes(target), path)
}

#[cfg(windows)]
pub(crate) fn symlink(target: &[u8], path: &Path) -> io::Result<()> {
    let t = String::from_utf8_lossy(target).replace('/', "\\");
    std::os::windows::fs::symlink_file(t, path)
}
