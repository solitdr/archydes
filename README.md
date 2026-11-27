# Archydes archive format

Open specification, reference decoder and test vectors for Archydes archives (`.archy`).

Archydes archives deduplicate data across files and versions, recompress JPEGs and Deflate data
(Office, PDF, ZIP) without loss and restore every file bit for bit, carry checksums everywhere and
can hold recovery data that repairs damage. They can keep several versions (snapshots) and can be
encrypted.

**Anyone may read and write the format and build their own implementations without license
fees.** This repository makes sure an `.archy` archive can always be opened, with or without the
[Archydes app](https://archydes.com).

| | |
|---|---|
| [`SPEC.md`](SPEC.md) | The format, version 1.1 (English, reference version). German: [`SPEC.de.md`](SPEC.de.md) |
| [`testvectors/`](testvectors/) | Archives with their expected content; every implementation must pass them |
| `crates/` | The reference decoder in Rust and the `archydes` command line tool |

## The `archydes` tool

Lists, extracts, verifies and repairs archives. It does not create archives.

```sh
archydes info    backup.archy
archydes list -l backup.archy
archydes extract backup.archy -C target/folder
archydes verify  backup.archy
archydes repair  backup.archy          # writes backup-repaired.archy
# encrypted archives ask for the password, or take it from a file or ARCHYDES_PASSWORD
archydes extract --password-file pw.txt -C out backup.archy
```

`ahy` is a short alias for `archydes`.

### Download

Ready-made binaries are attached to each [release](https://github.com/solitdr/archydes/releases/latest):

| System | File |
|---|---|
| macOS 13 or later (Apple silicon and Intel, signed and notarized) | [`archydes-macos-universal.zip`](https://github.com/solitdr/archydes/releases/latest/download/archydes-macos-universal.zip) |
| Linux x86_64 (glibc 2.35 or later) | [`archydes-linux-x86_64.tar.gz`](https://github.com/solitdr/archydes/releases/latest/download/archydes-linux-x86_64.tar.gz) |
| Linux arm64 (glibc 2.35 or later) | [`archydes-linux-arm64.tar.gz`](https://github.com/solitdr/archydes/releases/latest/download/archydes-linux-arm64.tar.gz) |

Next to each file is its SHA-256 (`….sha256`). Unpack the archive and put
`archydes` (and `ahy`, if you like) somewhere on your `PATH`, for example `/usr/local/bin`.

Windows is not supported yet.

### Build from source

Needs Rust 1.100 or later and a C compiler (zlib, Zstandard and liblzma are built in).

```sh
cargo build --release --locked -p archydes-cli
./target/release/archydes --help
python3 testvectors/check.py           # runs the test vectors against the build
```

## Crates

| Crate | Content |
|---|---|
| `archydes-format` | Header, segments, footer, index (CBOR), opening with fallbacks, encryption, writing the structures |
| `archydes-decode` | Codecs, reverse transformations, extraction with metadata, verification |
| `archydes-recovery` | Recovery data (Reed-Solomon): check, repair, rebuild the footer |
| `archydes-zlib` | zlib 1.3.1, bundled unchanged, for bit-exact Deflate (`ZLIB_EXACT`) |
| `archydes-cli` | The `archydes` tool |

`vendor/preflate-rs` is a fork of [preflate-rs](https://github.com/microsoft/preflate-rs) 0.7.6
(Apache-2.0) used for `PREFLATE`; [`FORK.md`](vendor/preflate-rs/FORK.md) describes the changes.
`fuzz/` holds the fuzz targets (`cargo fuzz`, nightly Rust).

Comments in the code sometimes name design decisions as `D-…`; these refer to SOLIT's internal
design notes. Everything a decoder needs is in the specification.

## Reporting problems

Bugs and questions about the specification: [issues](https://github.com/solitdr/archydes/issues).
Security problems (for example in the decoder or the encryption): please report them privately,
see [`SECURITY.md`](SECURITY.md).

## License

- Code: either of MIT ([`LICENSE-MIT`](LICENSE-MIT)) or Apache 2.0 ([`LICENSE-APACHE`](LICENSE-APACHE)), at your option.
  `archydes-zlib` also contains zlib (zlib license); `archydes-recovery` uses `reed-solomon-simd`
  (MIT AND BSD-3-Clause, Leopard-RS). Binary releases carry all notices in `THIRD-PARTY-NOTICES.txt`.
- Specification (`SPEC.md`, `SPEC.de.md`) and test vectors: [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/).

© 2026 SOLIT SRL. “Archydes” is a trademark of SOLIT SRL. The licenses above cover the code and
the specification, not the name; implementations of the format are welcome to say that they read
or write “Archydes archives (.archy)”.
