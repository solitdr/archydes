# Changelog

## archydes 1.0.0 · specification 1.1 – 2026

First public release.

- Specification 1.1: format 1.0 (deduplication, reverse transformations, recovery data,
  snapshots) and 1.1 (encryption with XChaCha20-Poly1305 and Argon2id).
- Reference decoder in Rust and the `archydes` tool: `info`, `list`, `extract`, `verify`, `repair`.
- Test vectors with a checker (`testvectors/check.py`).
