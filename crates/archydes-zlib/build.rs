//! Builds the unchanged zlib 1.3.1 sources with Z_PREFIX, so the symbols (z_deflate …) never
//! clash with another zlib in the same process (for example the system zlib in the app).

fn main() {
    let dir = "zlib-1.3.1";
    let files = ["adler32.c", "crc32.c", "deflate.c", "inffast.c", "inflate.c", "inftrees.c", "trees.c", "zutil.c"];
    let mut b = cc::Build::new();
    b.include(dir).define("Z_PREFIX", None).define("HAVE_UNISTD_H", None).warnings(false).opt_level(2);
    for f in files {
        b.file(format!("{dir}/{f}"));
        println!("cargo:rerun-if-changed={dir}/{f}");
    }
    b.compile("archydes_zlib");
}
