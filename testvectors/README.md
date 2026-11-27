# Test vectors

Archives for SPEC A14. A conforming decoder extracts every snapshot listed in
[`manifest.json`](manifest.json) with exactly the entries given there: kind, permission bits,
size, SHA-256 of the content and link targets. The files never change once published; new cases
get new files.

| File | Tests |
|---|---|
| `empty.archy` | One empty folder, no file data |
| `single-file.archy` | One small file |
| `dedup.archy` | Identical files and a file that differs in 16 bytes share chunks |
| `metadata.archy` | Folders, empty folder, symlink, hard link, duplicate file, extended attribute (`com.example.x` on `d/a.txt`) |
| `level-fast.archy`, `level-max.archy` | The content of `metadata.archy` at other compression levels |
| `transforms.archy` | `JPEG_FROM_JXL`, `ZLIB_EXACT`, `PREFLATE` in a JPEG, a ZIP container and a PDF; bit-exact output |
| `recovery.archy` | Recovery data over the whole file |
| `recovery-damaged.archy` | 512 overwritten bytes; `verify` reports them, `repair` restores `recovery.archy` byte for byte |
| `generations.archy` | Three generations; snapshot 1 removed, snapshot 2 left |
| `generations-interrupted.archy` | The same without its last 30 bytes: the second generation applies, the rest is an interrupted append |
| `encrypted-1.1.archy` | Format 1.1, encrypted. Password `Prüfung 1.1` (also accepted in NFD); `prüfung 1.1` is wrong |

Known-answer values for the key derivation and the encryption (SPEC A11) are in
[`crates/archydes-format/tests/crypto_vectors.rs`](../crates/archydes-format/tests/crypto_vectors.rs).

## Checking an implementation

```sh
python3 testvectors/check.py                      # the archydes tool from target/release or PATH
python3 testvectors/check.py --archydes ./my-tool # any tool with the same commands
```

Other implementations can read `manifest.json` directly. Extended attributes are not part of
the manifest, because Python cannot read them portably.

The test vectors are licensed under CC BY 4.0, like the specification.
