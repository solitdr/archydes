# preflate-rs, Archydes fork

This folder is a modified copy of **preflate-rs 0.7.6** (Microsoft Corporation, Apache-2.0),
taken unchanged from crates.io on 26 November 2026. The modifications were made by SOLIT SRL
for the Archydes archive format and are licensed under Apache-2.0 like the original
(see `LICENSE`). Upstream: <https://github.com/microsoft/preflate-rs>.

Version of the fork: `0.7.6+archydes.1`. Format id of its correction data, as stored in the
`ver` parameter of PREFLATE parts (Archydes SPEC A7): `preflate-rs-0.7.6/archydes-rc-1`.

## Why

Upstream encodes its correction data with the `cabac` crate, which is licensed
LGPL-3.0-or-later. Archydes uses no GPL or LGPL code. The fork replaces that coder with an own
one. The code of `cabac` was not looked at; the new coder follows the public description of the
binary range coder of LZMA.

## Changes (Apache-2.0 §4 b)

| File | Change |
|---|---|
| `Cargo.toml` | dependency `cabac` removed, version `0.7.6+archydes.1` |
| `src/cabac_codec.rs` | removed |
| `src/range_coder.rs` | new: adaptive binary range coder (11-bit probabilities, shift 5, 32-bit range, carry propagation as in LZMA), unary and fixed-width helpers; never panics on any input |
| `src/correction_codec.rs` | new: `PredictionEncoderRc` / `PredictionDecoderRc` behind the upstream traits `PredictionEncoder` / `PredictionDecoder`. `encode_difference` / `decode_difference` and the collection of default runs are taken from `cabac_codec.rs`; the bit-level coding is new (see below) |
| `src/lib.rs`, `src/statistical_codec.rs`, `src/tree_predictor.rs`, `src/stream_processor.rs` | use `correction_codec` instead of `cabac_codec`; debug output via `cabac` removed |
| `src/stream_processor.rs` (`recreate_blocks`) | bound on the number of rebuilt deflate blocks: error after more than 64 blocks in a row that consume no input, or more than `input / 16 + 4096` blocks. Hostile correction data used to grow memory without limit (found by fuzzing, 26 November 2026) |
| `src/token_predictor.rs` (`recreate_block`) | reserves at most as many tokens as input bytes are left, instead of the token count from the correction data (up to 2^32; found by fuzzing) |
| `src/tree_predictor.rs` (`recreate_tree_for_block`) | literal, distance and code length counts from the correction data are bounded (316 / 32 / 19) before they size a vector (up to 2^32 before; found by fuzzing) |
| `CLAUDE.md`, `.cargo_vcs_info.json`, `Cargo.toml.orig` | removed (not part of the build) |
| `FORK.md` | this file |

Everything else (`deflate/`, `estimator/`, prediction, hash chains, the container of the
correction data with `bitcode`) is unchanged.

## Correction data `archydes-rc-1`

The encoder collects all corrections first and writes them at `finish`, in the order the
decoder asks for them:

1. For each of the 17 correction types (`CodecCorrection` in order, without `MAX`): one bit
   "this type has a non-default value somewhere", all with one shared context.
2. Then for each collected action, in order of occurrence:
   - a **run of `n` defaults** (only for types that have a non-default value): bit 1 in the
     type's `default_signal` context, then `n - 1` with `write_exp` in the type's run contexts;
   - a **correction `v` ≠ 0**: bit 0 in the type's `default_signal` context, then `v - 1` with
     `write_exp` in the type's value contexts.
3. Flush of the range coder (5 bytes).

`write_exp(x)`: `b` = bit length of `x` (0–32) in unary (context `min(k, 31)` for position
`k`; the terminating zero is left out when `b = 32`), then for `b > 1` the `b - 1` bits below
the leading one, most significant first (context `min(i, 31)` for bit `i`).

Each probability starts at 1024 of 2048. The decoder reads bytes past the end as 0.

The tests `correction_codec::tests::encoding_is_fixed` and the vectors in
`archydes-decode/tests/vectors.rs` fix these bytes. A change that breaks them needs a new `ver`.

## Tests

The upstream unit tests need the `samples/` folder of the upstream repository next to this
folder (`open/vendor/samples`, not part of the Archydes repository). With it, all 52 pass
(26 November 2026).
