# Archydes Archive Format – Specification

Version 1.1 · 26 November 2026 · © 2026 SOLIT SRL

**Anyone may read and write this format and build their own implementations without license fees.**

This specification describes format versions 1.0 (unencrypted) and 1.1 (encrypted).

This specification is licensed under [Creative Commons Attribution 4.0 International (CC BY 4.0)](https://creativecommons.org/licenses/by/4.0/). The reference implementation for reading (libraries and the command-line tool `archydes`) is licensed under `MIT OR Apache-2.0`.

A German version is in [SPEC.de.md](SPEC.de.md). If the two differ, this English version applies; please report the difference.

## A1. Goal

The Archydes format is an archive format that combines three properties not found together in any common format:

1. **Deduplication:** Identical data is stored only once, including across file boundaries and versions.
2. **Recompression:** Files that are already compressed (JPEG, JPEGs in PDF scans, Deflate data in PDF/DOCX/XLSX/ZIP) are reduced further without loss and restored **bit-exactly** on extraction.
3. **Long-term safety:** Checksums everywhere, optional recovery data (Reed-Solomon) for repairing damaged archives, an open specification, a versioned structure.

In addition, **multiple versions** in one archive (snapshots, A10) and **encryption** (A11) are part of the format.

## A2. Design principles

1. **Bit-exactness is sacred.** Every extracted file must match the original byte for byte. Before writing, the packer verifies every transformation by reversing it. If the verification fails, the file is stored unchanged (RAW).
2. **Extensible through identifiers.** Every codec and every transformation has a numeric identifier. New methods get new identifiers; old ones remain valid. A decoder that does not know an identifier reports a clear error and does not guess.
3. **Everything is verified.** Header, segments, packs and original files carry checksums or hashes.
4. **Robust against partial damage.** A damaged region should make only the affected files unreadable, not the whole archive. With recovery data, damage should be repairable.
5. **Append only.** New versions are appended at the end; existing data is never overwritten. A crash while writing must not destroy the previous version.
6. **Open and long-lived.** The specification is published. The command-line tool `archydes` for listing, extracting, verifying and repairing is open source (`MIT OR Apache-2.0`), so that extraction never depends on commercial software. Only well-specified building blocks are used (CBOR, BLAKE3, zstd, LZMA2, ISO/IEC 18181).
7. **Parallelizable.** Packs are compressed and decompressed independently of each other, so that all CPU cores can be used.

## A3. Terms

| Term | Meaning |
|---|---|
| **Segment** | Basic unit of the file: header plus payload (pack, index, recovery data …) |
| **Chunk** | Block of data after splitting a stream (content-defined, approx. 256 KiB). Identifier: BLAKE3-256 of the content |
| **Pack** | Group of chunks compressed together (solid) with one codec; target 16 MiB uncompressed |
| **Stream** | Logical byte sequence = ordered list of chunks |
| **Recipe** | Instructions for producing the original file from streams (sequence of parts with transformations) |
| **Transformation** | Reversible conversion, e.g. JPEG XL → JPEG, inflated data → original Deflate stream |
| **Entry** | File, directory, symlink or hard link with metadata and recipe |
| **Snapshot** | State of a directory at one point in time = list of entries |
| **Index** | Table of contents: pack table, chunk table, all snapshots |
| **Generation** | Counter that increases with every append |

## A4. Basic encoding rules

- All integers in fixed structures: **little endian**.
- Checksum for headers: **CRC32C** (Castagnoli).
- Hash for contents: **BLAKE3**. Full length (32 bytes) for chunk IDs and file hashes; the first 16 bytes ("BLAKE3-128") for segment payloads.
- Structured data (index, metadata): **CBOR** (RFC 8949), deterministic encoding (RFC 8949 §4.2.1). Only a subset is used: unsigned and negative integers, byte and text strings, arrays, maps, `false`, `true`, `null`, each with definite length. No tags, no floating-point numbers, no indefinite lengths. A decoder may reject other CBOR items. It skips unknown keys in maps (forward compatibility).
- Timestamps: nanoseconds since 1970-01-01 UTC, signed 64-bit.
- File paths: bytes exactly as the file system returns them (on macOS mostly NFD), separator `/`, always relative. In addition, the NFC form is stored for display and comparison.

## A5. File layout

```
+--------------------------------------------------+
| Header (64 bytes, fixed)                         |
+--------------------------------------------------+
| Segment FORMAT_INFO (plain-text description)     |
| Segment KEY_INFO         (encrypted only, A11)   |
+--------------------------------------------------+
| Segment PACK  |  Segment PACK  |  …              |
+--------------------------------------------------+
| Segment KEY_INFO         (copy, encrypted only)  |
| Segment INDEX            (generation n)          |
| Segment INDEX_COPY       (identical)             |
+--------------------------------------------------+
| Segment RECOVERY         (optional)              |
+--------------------------------------------------+
| Footer (64 bytes, fixed)                         |
+--------------------------------------------------+
   … when a new version is appended, further PACK
     segments follow, then (encrypted only) a KEY_INFO
     copy, a new INDEX, INDEX_COPY, optionally RECOVERY
     and a footer. The last valid footer applies.
```

### A5.1 Header (offset 0, 64 bytes)

| Offset | Size | Field | Content |
|---|---|---|---|
| 0 | 8 | magic | `89 41 52 43 48 0D 0A 1A` (`\x89ARCH\r\n\x1A`, modeled on PNG: detects text-mode transfer errors) |
| 8 | 2 | format_major | 1 |
| 10 | 2 | format_minor | 0; 1 for encrypted archives (A11) |
| 12 | 4 | flags | State **at creation**, informative only; bits see below |
| 16 | 16 | archive_uuid | random UUID (v4) |
| 32 | 8 | created_ns | creation time |
| 40 | 20 | reserved | 0 |
| 60 | 4 | crc32c | over bytes 0–59 |

Archive flags (in the header and in the footer):

| Bit | Name | Set when |
|---|---|---|
| 0 | `ENCRYPTED` | the archive is encrypted (A11) |
| 1 | `RECOVERY` | recovery data is present: `recovery_offset` in the footer is not 0 (A9) |
| 2 | `MULTIPLE_SNAPSHOTS` | the index holds more than one snapshot |
| 3–31 | – | reserved, 0 |

The header is never written again after creation (append only). The flags in the **last valid footer** (A5.4) are authoritative for the current state. A decoder must not infer anything about the current state from the header flags. Exception: bit 0 (encrypted) cannot change; header and footer must agree on it, otherwise the archive is considered damaged.

**Version rule:** A decoder rejects a higher `format_major`. It may read a higher `format_minor`. Unknown segment types (A5.2) with the `CRITICAL` flag set mean that the archive needs a newer decoder: the decoder must not present its result as complete (`verify` reports such a segment as a problem). Unknown segment types without the flag are skipped.

### A5.2 Segment header (40 bytes)

| Offset | Size | Field | Content |
|---|---|---|---|
| 0 | 4 | magic | `AHSG` |
| 4 | 2 | type | see table |
| 6 | 2 | flags | bit 0 `CRITICAL`, bit 1 `ENCRYPTED`, bits 2–15 reserved (0) |
| 8 | 8 | payload_len | length of the payload in bytes |
| 16 | 16 | payload_hash | BLAKE3-128 of the payload (as stored) |
| 32 | 4 | reserved | 0 |
| 36 | 4 | crc32c | over bytes 0–35 |

| Type | Name | Critical | Content |
|---|---|---|---|
| 0x0001 | PACK | yes | compressed chunks |
| 0x0002 | INDEX | yes | table of contents (CBOR, zstd-compressed) |
| 0x0003 | INDEX_COPY | no | identical copy of the INDEX |
| 0x0004 | RECOVERY | no | Reed-Solomon data |
| 0x0005 | FORMAT_INFO | no | UTF-8 plain text: format name, version, URL of the specification, pointer to the free extraction tool `archydes` |
| 0x0006 | PLAIN_TOC | no | optional, unencrypted archives only: file list as UTF-8 plain text (for humans, readable without software) |
| 0x0007 | KEY_INFO | yes | encrypted archives only (A11): Argon2 parameters, salt, wrapped data key |
| 0x0000, 0x0008–0x7FFF | – | – | reserved for future versions |
| 0x8000–0xFFFF | – | no | free for experiments, to be ignored by decoders |

`CRITICAL` means that a decoder cannot read the archive correctly without understanding the segment. A packer sets it exactly as in the column "Critical". For the types in this table the table decides: a decoder ignores the flag and treats the segment as the table says, even if the flag disagrees. The flag matters only for unknown types (A5.1, version rule). Types 0x8000–0xFFFF are always ignored, whatever the flag says. `ENCRYPTED` is set exactly on the payloads that are encrypted (PACK, INDEX, INDEX_COPY of an encrypted archive, A11).

The magic `AHSG` makes it possible to find segments again by scanning the file when the index is damaged.

### A5.3 PACK payload

```
pack_header (CBOR map, length prefixed as u32):
  { "codec": uint, "ulen": uint, "chunks": uint, "level": uint (informative) }
compressed_data
```

The chunks of a pack are concatenated in the order of the chunk table (index) and compressed as one block. Their position in the uncompressed pack is given in the chunk table.

**Codec registry:**

| ID | Codec | Note |
|---|---|---|
| 0 | none | for incompressible data (JXL, MP4, HEIC …) |
| 1 | zstd | default for "Fast"; frame format according to RFC 8878 |
| 2 | LZMA2 | raw stream, parameter (dict_size) in the pack_header as `"dict"` |
| 3–15 | reserved | e.g. Brotli, context mixing |

**Rule:** If a codec saves less than 2 % (0.5 % at the "Maximum" level) compared to `none`, `none` is stored. This rule applies only to the packer; a decoder reads every codec.

**Limits:** `ulen` of a pack at most 64 MiB, CBOR pack_header at most 4 KiB, `dict` for LZMA2 between 4 KiB and 256 MiB. `ulen` and `codec` in the pack_header must match the entry in the pack table of the index.

### A5.4 Footer (last 64 bytes of the file)

| Offset | Size | Field |
|---|---|---|
| 0 | 8 | magic `AHYEND\0\0` |
| 8 | 2 | format_major |
| 10 | 2 | format_minor |
| 12 | 4 | flags (archive flags, A5.1; here **authoritative** for the state of this generation) |
| 16 | 8 | index_offset (offset of the INDEX segment header) |
| 24 | 8 | index_copy_offset |
| 32 | 8 | recovery_offset (offset of the segment header of the newest RECOVERY segment, 0 = none) |
| 40 | 8 | generation |
| 48 | 8 | key_info_offset (format 1.1 encrypted: offset of the KEY_INFO segment header of this generation; otherwise 0) |
| 56 | 4 | reserved |
| 60 | 4 | crc32c over bytes 0–59 |

A footer directly follows the last segment of its generation (INDEX_COPY, or RECOVERY if the generation writes one). Bytes that look like a footer elsewhere, for example in the parity of a RECOVERY segment (A9), are not a footer: a decoder accepts a footer only if the segment at the largest of `index_offset`, `index_copy_offset` and `recovery_offset` ends exactly at the footer, unless that segment header is unreadable.

**Opening an archive:** check the header → read the footer → read the INDEX and check its hash. On an error, INDEX_COPY is used. If the footer itself is broken, the decoder searches backwards from the end of the file for the last valid `AHYEND` or INDEX segment.

## A6. Table of contents (INDEX)

CBOR map, then zstd-compressed (codec in a 1-byte prefix: 1 = zstd).

```
{
  "v": 1,                         ; index version
  "generation": uint,
  "created_ns": int,
  "cdc": { "alg": "fastcdc-2020", "min": 65536, "avg": 262144, "max": 1048576 },
  "packs": [ { "off": uint, "clen": uint, "ulen": uint, "codec": uint, "hash": bstr(16) } ... ],
                                  ; off = offset of the PACK segment header, clen = length of compressed_data,
                                  ; hash = BLAKE3-128 of the whole payload (= payload_hash of the segment header)
  "chunks": {                     ; column-wise for compactness
    "id":     bstr(32 × n),       ; BLAKE3-256 per chunk, concatenated
    "pack":   [uint ...],         ; index into "packs"
    "off":    [uint ...],         ; offset in the uncompressed pack
    "len":    [uint ...]
  },
  "snapshots": [ Snapshot ... ]   ; all versions, oldest first
}

Snapshot = {
  "id": uint, "time_ns": int, "comment": tstr, "source": tstr (names of what was packed, e.g. "Photos, Documents"; informative, never an absolute path),
  "entries": [ Entry ... ]
}

Entry = {
  "path": bstr, "path_nfc": tstr,
  "kind": 0 file | 1 directory | 2 symlink | 3 hard link,
  "mode": uint, "mtime_ns": int, "btime_ns": int (optional),
  "xattr": { tstr: Stream ... } (optional; macOS: Finder tags, quarantine, resource fork),
  "target": bstr (symlink target, or path of the hard link's original),
  "size": uint, "hash": bstr(32),          ; BLAKE3-256 of the original file
  "recipe": Recipe                          ; files only
}

Stream = [ uint ... ]            ; indices into the chunk table
Recipe = [ Part ... ]            ; original file = concatenation of the part outputs
Part   = [ transform_id: uint, params: map, inputs: [ Stream ... ] ]
```

`source` is for display only. A packer must not write an absolute path into it (nor a path starting with `~` or climbing with `..`): the archive would otherwise reveal where the files were on the packing machine. When it writes a new index, it reduces such values in older snapshots to their last name.

Rules for entries:

- `size`, `hash` and `recipe` exist only for files (`kind` 0).
- A hard link (`kind` 3) refers with `target` to the path of a **file in the same snapshot**; its data is the data of that file.
- The values of `xattr` are streams like file contents (long values are therefore also split and deduplicated).
- `mode` contains only the permission bits (`0o7777`); the type is given by `kind`.
- A packer stores the entries sorted by the bytes of `path`; a decoder must not rely on this.

Identical files refer to the same chunks (file-level deduplication follows automatically). The index of a new generation always contains all remaining snapshots and all packs and chunks of the archive, including those no snapshot uses any more (they are only removed by optimizing, A10); older INDEX segments are then only history.

## A7. Transformations

A recipe consists of parts. Each part produces one section of the original file from its input streams.

| ID | Name | Inputs | Parameters | Output |
|---|---|---|---|---|
| 0 | RAW | 1 stream | – | stream unchanged |
| 1 | ZLIB_EXACT | 1 stream (inflated data) | `wbits`, `level`, `memlevel`, `strategy`, `impl` (registry see below) | Deflate stream produced by exactly this zlib version with these parameters |
| 2 | PREFLATE | 2 streams (inflated data, correction data) | `ver` (preflate version), `wbits` | original Deflate stream of any origin |
| 3 | JPEG_FROM_JXL | 1 stream (JPEG XL codestream with JPEG reconstruction data) | `enc` (informative, e.g. `"libjxl 0.11"`) | original JPEG according to ISO/IEC 18181-2 (JPEG bitstream reconstruction) |
| 4–63 | reserved | | | e.g. PNG_IDAT, GZIP file, MP3, HEIC |

**Notes:**

- **ZLIB_EXACT** is the fast path for data produced by zlib itself. The decoder must ship the specified zlib version (vendored), because other implementations (zlib-ng, libdeflate, Apple's) produce different bytes. Allowed parameter values (as for zlib's `deflateInit2`): `wbits` 8 to 15 (zlib wrapper), −9 to −15 (raw Deflate; −8 is not allowed, because zlib silently turns it into −9) or 24 to 31 (gzip wrapper); `level` 0 to 9; `memlevel` 1 to 9; `strategy` 0 to 4. The decoder reports other values as damage. Registry of values for `impl`: `"zlib-1.3.1"` (unmodified source code of zlib 1.3.1). New values are added only together with test vectors; a version once assigned remains readable forever, so the decoder ships it permanently, on all platforms. The decoder reports an unknown value as an error.
- **PREFLATE** also reconstructs Deflate streams from Microsoft Office, Adobe, etc. The correction data is usually very small. The parameter `ver` identifies the format of the correction data, not just a software version; every assigned `ver` remains readable permanently. Registry of values for `ver`: `"preflate-rs-0.7.6/archydes-rc-1"`. Its reference is a fork of preflate-rs 0.7.6 (`vendor/preflate-rs`, Apache-2.0) whose correction data is encoded by its own adaptive binary range coder following the LZMA scheme (11-bit probabilities, adaptation by 1/32). The byte sequence is described in the fork's `FORK.md` and fixed by test vectors. The correction data is therefore not interchangeable with unmodified preflate-rs. `wbits` is always `-15`: the output is a raw Deflate stream without a wrapper. A zlib wrapper (2-byte header, 4-byte Adler-32) is stored in RAW parts before and after it. The decoder reports an unknown value of `ver` as an error.
- **JPEG_FROM_JXL** is standardized in the JPEG XL standard. The reconstruction therefore does not depend on any particular software in the long term. This is an important argument for long-term safety. Not every JPEG can be represented this way (e.g. arithmetic coding, some CMYK or damaged files). The mandatory verification detects such files; they are stored RAW.

**Preprocessors (packer only, not part of the format):** They split a file into parts.

| File type | Procedure |
|---|---|
| JPEG | whole file → JPEG_FROM_JXL |
| PDF | parts: RAW (remainder), JPEG_FROM_JXL (streams with `/DCTDecode`), ZLIB_EXACT/PREFLATE (streams with `/FlateDecode`) |
| ZIP containers (DOCX, XLSX, PPTX, ODT, EPUB, ZIP, Pages …) | RAW (headers, directory), ZLIB_EXACT/PREFLATE (entries with method 8), JPEG_FROM_JXL (stored JPEGs, method 0). A JPEG inside a Deflate entry is only inflated, not converted further |
| everything else | RAW |

Later: PNG (concatenate IDAT streams), GZIP files, JPEGs in other containers.

**Mandatory verification when packing:** For every file, the recipe is reversed immediately and compared with the BLAKE3 hash of the original. The recipe is used only if they match; otherwise RAW. The reversal uses **the same decoder code as the open extraction tool**, not the encoder. This guarantees that the open tool can extract every written file bit-exactly. On extraction, the hash is always checked.

## A8. Chunking and packs

- The output streams of the preprocessors are split with **FastCDC** (content-defined): min 64 KiB, average 256 KiB, max 1 MiB. The parameters are stored in the index. Smaller files form a single chunk.
- Chunk ID = BLAKE3-256 of the chunk content. If an ID is already known, the chunk is not stored again.
- Chunks are distributed to packs by **type class** so that solid compression works well: text/XML, binary data, already entropy-coded (JXL, HEIC, MP4 …). Within a class, sort by file extension and path.
- Target pack size 16 MiB uncompressed. Packs are independent and are compressed in parallel.

**Presets** (recommendation for packers, not part of the format):

| Level | Codec | Transformations | Purpose |
|---|---|---|---|
| Fast | zstd 3 | none | everyday use, very fast |
| Standard | zstd 19, or LZMA2 for text | JPEG, JPEG in PDF, ZLIB_EXACT | good balance |
| Maximum | LZMA2 (preset 9e) | all, including PREFLATE | archiving |

## A9. Recovery data (RECOVERY)

**Coverage.** Each RECOVERY segment protects a contiguous range `[start, end)` of the file. `end` is the offset of its own segment header. `start` is the end of the previous RECOVERY segment (segment header plus payload), 0 for the first one. The chain of all RECOVERY segments therefore covers the file without gaps up to the newest RECOVERY segment, including the file header. Older RECOVERY segments and footers lie within the range of the respective newer one and are thus protected themselves. A packer writes RECOVERY after INDEX and INDEX_COPY and immediately before the footer; `recovery_offset` in the footer points to it, and the archive flag `RECOVERY` (A5.1) is set. The segment is not critical (segment flag `CRITICAL` cleared, A5.2): a decoder without repair support may skip it.

**Slices and groups.**

- The range is divided into `N = ceil((end − start) / 65536)` slices of **64 KiB**. For hashing and encoding, the last slice is padded with zero bytes to 64 KiB; the zeros are not stored.
- There are `G = ceil(N / 1024)` groups. The slices are distributed **interleaved**: slice `i` belongs to group `i mod G` and is original slice number `i div G` there. Group `g` thus has `n_g = ceil((N − g) / G)` data slices (at most 1024) and `r_g = max(1, ceil(n_g × ratio))` parity slices.
- Reason for interleaving: contiguous damage (defective sector, truncated download, overwritten block) is spread evenly across all groups. A run of up to `Σ r_g − G` consecutive slices is always repairable, i.e. almost the entire parity. At the same time, encoding needs only 64 MiB of memory per group.
- Redundancy is configurable: 0 % (off), 5 % (default), 10 % or 20 %, per generation. The decoder does not read the ratio, only `[n_g, r_g]` from the header.

**Payload layout.** All numbers little endian.

| Part | Content |
|---|---|
| Front header | `u32 H`, `H` bytes of CBOR, `u32` CRC32C of the CBOR bytes |
| Parity | for `g = 0 … G−1` the `r_g` parity slices of the group, 65,536 bytes each |
| Table | BLAKE3-128 of each data slice (`i = 0 … N−1`), then of each parity slice in the order above; followed by `u32` CRC32C of the table |
| Table, copy | the same bytes again |
| Back header | `H` bytes of CBOR, `u32` CRC32C, `u32 H` |

Header: `{"v": 1, "alg": "rs-leopard-gf16", "slice": 65536, "start": uint, "end": uint, "groups": [[n, r] ...], "prev": uint}`. `prev` is the offset of the previous RECOVERY segment, 0 for the first one. A decoder checks that `groups` corresponds exactly to the interleaving of `[start, end)` and rejects the header otherwise.

**Self-protection.** The newest RECOVERY segment and the last footer lie behind the protected range. Therefore:

- The table also contains the hashes of the **parity slices**. A damaged parity slice counts as a missing slice. A group is repairable as long as damaged data and parity slices together number at most `r_g`. Damage in the parity part only costs capacity.
- Header and table are each stored twice and carry their own CRC32C. If the CRC is wrong in both table copies, a slice is considered intact if its hash matches either of the two copies.
- The footer contains only offsets that can be recomputed from the segments. `archydes repair` rewrites it.

**Locating.** The decoder searches for the RECOVERY segment in this order, without relying on the footer or the segment header:

1. via `recovery_offset` of the last footer;
2. via the back header that ends directly before the footer (or at the end of the file if the footer is missing);
3. by searching backwards for a valid segment header of type RECOVERY.

In every case, `end` must equal the offset of the segment, and the segment must lie entirely within the file.

**Repair.**

1. Every data and parity slice is checked against the table.
2. Every group with damaged data slices is decoded if enough intact slices remain. Every recovered slice is checked against the table again before it is written back.
3. If all data is then intact and RECOVERY itself was damaged, the RECOVERY segment is rewritten with the same layout. If data damage remains, RECOVERY is left unchanged, so that no parity is computed over damaged data.
4. If the footer behind the RECOVERY segment is unusable, it is rewritten from the last INDEX and INDEX_COPY before the RECOVERY segment (and, encrypted, the KEY_INFO copy before them). Its flags are those a packer writes: `ENCRYPTED` from the file header (it cannot change), `RECOVERY`, and `MULTIPLE_SNAPSHOTS` if the index holds more than one snapshot. Without the password the index of an encrypted archive cannot be read; then `MULTIPLE_SNAPSHOTS` and `generation` (plus 1) come from the previous footer. The file header must not be used for `MULTIPLE_SNAPSHOTS`: it shows the state at creation.

**Chain.** The decoder reaches older ranges via `prev`: the previous RECOVERY segment is found via its front header (`prev` + 40) or, if that is damaged, via the back header that ends exactly at `start` of the newer range. It must hold that `end = prev` and segment end `= start` of the newer range; the ranges have no gaps and do not overlap. `repair` checks and repairs every range of the chain, newest first; step 4 (footer) applies only to the newest. If a generation has no RECOVERY (ratio 0), its footer keeps pointing to the previous segment and keeps the flag `RECOVERY` as long as `recovery_offset` is not 0; the generation itself is then unprotected, and the next RECOVERY segment also covers everything since then.

If a group cannot be repaired, all files whose packs lie outside the damage remain extractable. The report names the affected files.

**Limitation.** If the file is **truncated**, the RECOVERY segment is the first thing lost, because it is at the end. Then only the backward search for the last readable index (A5.4) helps. A later option is a separate recovery file next to the archive.

**Method `rs-leopard-gf16`.** Reed-Solomon erasure code over GF(2^16) following Leopard-RS (C. A. Taylor); the slice size is a multiple of 64 bytes. The reference is the Rust library `reed-solomon-simd` from version 3.0. A mathematical description (field polynomial, basis, ordering of the slices) will be added to this section in a later revision, so that independent implementations are possible without this library. The test vectors additionally fix the encoding.

## A10. Versions (snapshots)

**Generations.** An archive grows only at the end. Each generation is appended after the end of the last valid footer: new PACK segments (only chunks the archive does not yet have), then in encrypted archives a copy of KEY_INFO (A11), then INDEX and INDEX_COPY with **all** snapshots, chunks and packs, then optionally RECOVERY over the new range (A9), then the footer. `generation` increases by 1. Whatever lies before the end of the last valid footer is never written again.

**Validity.** A generation becomes valid only once its footer has been written completely. A packer flushes everything before the footer with `fsync`, then writes the footer and flushes it as well. After a crash before that point, the decoder finds the footer of the previous generation via the backward search (A5.4); that generation remains readable unchanged.

**Leftovers of an aborted append.** A decoder that cannot read the last footer and finds, via the backward search, a valid footer with a readable INDEX checks the bytes after it. They are considered leftovers of an aborted append and do not belong to the archive if

- from the end of the found footer onwards, only segments of types PACK, KEY_INFO (in encrypted archives, A11), INDEX, INDEX_COPY and RECOVERY follow, the last of which may be incomplete (header truncated, consisting of zero bytes, or payload extending beyond the end of the file), and no readable footer;
- the last 64 bytes of the file do not begin with the footer magic;
- no INDEX_COPY or RECOVERY segment ends exactly 64 bytes before the end of the file.

The last two conditions detect a complete newer generation with a damaged footer; that is not a leftover but damage that `repair` can fix. `verify` reports leftovers as a notice, not as damage. The next write operation truncates them before appending; it does not modify an archive with damage.

**Concurrent access.** A packer locks the archive exclusively while appending (`flock`/`LockFileEx`) and aborts if it is already locked. Readers need no lock: whatever lies before the footer they use does not change.

**Snapshot numbers.** A new snapshot gets the largest existing `id` plus 1. Numbers are not reused, not even after deletion.

**Deleting a snapshot.** A new generation without PACK segments: (encrypted: KEY_INFO copy,) INDEX and INDEX_COPY without the deleted snapshots, optionally RECOVERY, footer. Chunks and packs remain in the index and in the file (A6), until the archive is optimized; the last snapshot cannot be deleted.

**Optimizing.** Rewrites the archive with only the chunks that some snapshot still uses (recipes and extended attributes). Packs whose chunks are all used are taken over unchanged, partially used ones are unpacked and repacked, unused ones are dropped. `archive_uuid` and `created_ns` of the file header are kept, `generation` increases by 1, RECOVERY covers the whole new file. The new file replaces the old one by renaming.

## A11. Encryption (format 1.1)

An encrypted archive has `format_minor = 1` and bit 0 (encrypted) set in the header and in every footer. Unencrypted archives remain format 1.0.

**What is encrypted.** The payloads of the PACK, INDEX and INDEX_COPY segments. FORMAT_INFO, KEY_INFO and RECOVERY remain plain text. PLAIN_TOC is forbidden. This protects the contents, names, sizes and dates of individual files, comments, extended attributes and chunk IDs. Still visible are the total size, the number and sizes of the segments, the number of generations, the creation time and the Argon2 parameters.

**Keys.**

```
KEK     = Argon2id v1.3 (password as UTF-8 in Unicode NFC, salt, m, t, p), 32 bytes
DEK     = 32 random bytes per archive, wrapped under KEK in KEY_INFO
k_seg   = BLAKE3-derive_key("archydes 2026-11 segment v1", DEK)
k_chunk = BLAKE3-derive_key("archydes 2026-11 chunk-id v1", DEK)
```

**KEY_INFO** (type 0x0007, critical, unencrypted). On creation it is placed directly after FORMAT_INFO; every generation writes a byte-identical copy before its INDEX, to which `key_info_offset` of its footer points. Payload: CBOR map

```
{ "v": 1, "kdf": "argon2id-1.3", "m": uint (KiB), "t": uint, "p": uint, "salt": bstr(16),
  "aead": "xchacha20-poly1305", "nonce": bstr(24), "wrapped": bstr(48) }
```

`wrapped` = XChaCha20-Poly1305(KEK, nonce, DEK, AAD) with the 16-byte tag at the end. AAD = `"archydes key v1"` (ASCII, 15 bytes) ‖ `archive_uuid` (16 bytes) ‖ deterministic CBOR of the map without `nonce` and `wrapped`. A decoder rejects the segment without computing anything if `v`, `kdf` or `aead` are unknown or the limits are violated: `m` 8,192 to 4,194,304 (8 MiB to 4 GiB), `t` 1 to 64, `p` 1 to 64, `m ≥ 8·p`. If the tag check fails, the password is wrong.

Locating: via `key_info_offset` of the footer in use; if the segment there is unusable, the first readable KEY_INFO when scanning from the start of the file (A5). All KEY_INFO segments of an archive are identical.

**Encrypted segments.** What is stored is `nonce (24 bytes) ‖ ciphertext ‖ tag (16 bytes)`, encrypted with `k_seg` and a random nonce per segment. The segment header carries flag bit 1 (encrypted); `payload_len` and `payload_hash` refer to the stored bytes. Structure verification, recovery and repair therefore need no password. AAD = `"archydes segment v1"` (ASCII, 19 bytes) ‖ `archive_uuid` ‖ class (1 byte: 1 = PACK, 2 = INDEX for INDEX and INDEX_COPY). INDEX_COPY is byte-identical to INDEX. Decryption yields the unencrypted content as before: pack_header and compressed data (A5.3), or codec byte and index (A6). `clen` in the index is the length of the compressed data before encryption; `hash` in the pack table is the `payload_hash` of the segment (over the ciphertext).

**Rules for decoders.** In an encrypted archive, PACK, INDEX and INDEX_COPY must be encrypted; in an unencrypted archive, no segment may carry the flag; otherwise the archive is considered damaged. A failed tag check on a PACK or INDEX is damage, like a wrong `payload_hash`.

**Chunk IDs.** With encryption, `BLAKE3-keyed(k_chunk, content)` instead of BLAKE3-256. The file hash in the entry (`hash`) remains BLAKE3-256 of the original file.

**Limitations.** Anyone with write access can cut off the newest generation; the archive then reads as it did before. Any modification of the data is detected.

## A12. Safety when extracting

- Reject paths containing `..`, absolute paths and empty path components (Zip Slip).
- Symlinks: never resolve outside the target directory. By default, create them as symlinks; do not follow them.
- Limits against decompression bombs: the index inflates to at most 1 GiB, packs to at most 64 MiB (A5.3), CBOR at most 32 levels deep, no length may extend beyond the end of the input. When extracting a file, abort as soon as more data is produced than `size` specifies. Check the total size in advance from the index.
- Extraction order: directories, files, hard links, **symlinks last**, then the metadata of the directories from the innermost outwards. Every parent path component must be a real directory (not a symlink). This ensures that extraction never writes through a symlink to a location outside the target directory.
- setuid and setgid bits are not restored by default. Existing files are not overwritten by default.
- A file whose hash does not match is deleted again and reported as damaged; the remaining files are still extracted.
- All parsers (header, segments, CBOR, recipes) treat input as untrusted and are fuzzed.

## A13. File extension and identifiers

- File extension: **`.archy`**.
- UTI (macOS): `do.com.solit.archydes.archive`, conforming to `public.data` and `public.archive`.
- MIME type: `application/x-archydes`.

## A14. Test vectors and conformance

The specification includes a folder `testvectors/` with small archives and their expected contents: empty archive, single file, deduplication, every transformation, recovery (with a deliberately damaged copy), multiple generations, an encrypted archive with a known password, and known-answer values for key derivation, wrapping of the data key, subkeys and sealing (A11). Every implementation must pass these vectors.
