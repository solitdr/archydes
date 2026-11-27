//! Safe paths (SPEC A12): no `..`, no absolute paths, no empty components.

use std::path::PathBuf;

/// The relative path for stored path bytes, or `None` if it could leave the destination.
pub fn safe_relative(p: &[u8]) -> Option<PathBuf> {
    if p.is_empty() || p[0] == b'/' || p.contains(&0) {
        return None;
    }
    for comp in p.split(|&b| b == b'/') {
        if comp.is_empty() || comp == b"." || comp == b".." {
            return None;
        }
        #[cfg(windows)]
        if comp.iter().any(|&b| b == b'\\' || b == b':') {
            return None;
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        Some(PathBuf::from(std::ffi::OsStr::from_bytes(p)))
    }
    #[cfg(not(unix))]
    {
        std::str::from_utf8(p).ok().map(PathBuf::from)
    }
}

#[cfg(test)]
mod tests {
    use super::safe_relative;

    #[test]
    fn rejects_escapes() {
        for bad in [&b""[..], b"/etc/passwd", b"../x", b"a/../../x", b"a//b", b"a/./b", b"a/", b"./a", b"a\0b"] {
            assert!(safe_relative(bad).is_none(), "{:?}", String::from_utf8_lossy(bad));
        }
        for good in [&b"a"[..], b"a/b/c.txt", b"..a", b"a..", b".hidden/x"] {
            assert!(safe_relative(good).is_some());
        }
    }
}
