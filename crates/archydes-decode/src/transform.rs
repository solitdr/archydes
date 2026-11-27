//! Reverse direction of the transformations (SPEC A7). The packer runs exactly this code for
//! its mandatory check, so whatever it writes, the open tool can rebuild.

use archydes_format::cbor::Value;
use archydes_format::consts::transform;
use archydes_format::{Error, Part, Result, corrupt};
use archydes_zlib::Params;

fn param<'a>(part: &'a Part, key: &str) -> Option<&'a Value> {
    part.params.iter().find(|(k, _)| k.as_text() == Some(key)).map(|(_, v)| v)
}

fn int(part: &Part, key: &str) -> Result<i32> {
    param(part, key)
        .and_then(Value::as_i64)
        .and_then(|v| i32::try_from(v).ok())
        .ok_or_else(|| corrupt(format!("ZLIB_EXACT: parameter {key} missing")))
}

/// Parameters of a ZLIB_EXACT part.
pub fn zlib_params(part: &Part) -> Result<Params> {
    match param(part, "impl").and_then(Value::as_text) {
        Some(archydes_zlib::IMPL) => {}
        Some(other) => return Err(Error::Unsupported(format!("ZLIB_EXACT implementation {other:?}"))),
        None => return Err(corrupt("ZLIB_EXACT: parameter impl missing")),
    }
    let p = Params {
        wbits: int(part, "wbits")?,
        level: int(part, "level")?,
        memlevel: int(part, "memlevel")?,
        strategy: int(part, "strategy")?,
    };
    if !p.valid() {
        return Err(corrupt(format!("ZLIB_EXACT: invalid parameters {p:?}")));
    }
    Ok(p)
}

/// The params map for a ZLIB_EXACT part (for the packer).
pub fn zlib_part_params(p: Params) -> Vec<(Value, Value)> {
    vec![
        (Value::text("impl"), Value::text(archydes_zlib::IMPL)),
        (Value::text("wbits"), Value::int(p.wbits as i64)),
        (Value::text("level"), Value::int(p.level as i64)),
        (Value::text("memlevel"), Value::int(p.memlevel as i64)),
        (Value::text("strategy"), Value::int(p.strategy as i64)),
    ]
}

/// Hands the bytes of input stream `k` of a part to a sink.
pub type InputFn<'a> = dyn FnMut(usize, &mut dyn FnMut(&[u8]) -> Result<()>) -> Result<()> + 'a;

/// Rebuilds the bytes of one recipe part into `sink`. Used by extraction and by the packer's
/// mandatory check (with the inputs still in memory).
pub fn rebuild_part(part: &Part, input: &mut InputFn, sink: &mut dyn FnMut(&[u8]) -> Result<()>) -> Result<()> {
    let inputs = |n: usize| {
        if part.inputs.len() == n {
            Ok(())
        } else {
            Err(corrupt(format!("{} needs exactly {n} input(s)", transform::name(part.transform))))
        }
    };
    match part.transform {
        transform::RAW => {
            inputs(1)?;
            input(0, sink)
        }
        transform::ZLIB_EXACT => {
            inputs(1)?;
            let params = zlib_params(part)?;
            let zerr = |e: archydes_zlib::Error| corrupt(format!("ZLIB_EXACT: {e}"));
            let mut deflater = archydes_zlib::Deflater::new(params).map_err(zerr)?;
            // The sink's error, carried out of zlib's callback.
            let failed: std::cell::RefCell<Option<Error>> = Default::default();
            let mut forward = |b: &[u8]| match sink(b) {
                Ok(()) => true,
                Err(e) => {
                    *failed.borrow_mut() = Some(e);
                    false
                }
            };
            let stopped = || corrupt("ZLIB_EXACT: output stopped");
            let result = input(0, &mut |data| {
                if deflater.push(data, &mut forward).map_err(zerr)? { Ok(()) } else { Err(stopped()) }
            })
            .and_then(|()| if deflater.finish(&mut forward).map_err(zerr)? { Ok(()) } else { Err(stopped()) });
            if let Some(e) = failed.take() {
                return Err(e);
            }
            result
        }
        transform::JPEG_FROM_JXL => {
            inputs(1)?;
            let mut jxl = Vec::new();
            input(0, &mut |d| {
                if jxl.len() + d.len() > MAX_JXL {
                    return Err(Error::Limit("JPEG_FROM_JXL: input larger than 512 MiB".into()));
                }
                jxl.extend_from_slice(d);
                Ok(())
            })?;
            jpeg_from_jxl(&jxl, sink)
        }
        transform::PREFLATE => {
            inputs(2)?;
            match param(part, "ver").and_then(Value::as_text) {
                Some(PREFLATE_VER) => {}
                Some(other) => return Err(Error::Unsupported(format!("PREFLATE version {other:?}"))),
                None => return Err(corrupt("PREFLATE: parameter ver missing")),
            }
            let mut plain = Vec::new();
            let mut corrections = Vec::new();
            for (k, buf, max) in [(0, &mut plain, MAX_PREFLATE_PLAIN), (1, &mut corrections, MAX_PREFLATE_PLAIN)] {
                input(k, &mut |d| {
                    if buf.len() + d.len() > max {
                        return Err(Error::Limit("PREFLATE: input too large".into()));
                    }
                    buf.extend_from_slice(d);
                    Ok(())
                })?;
            }
            sink(&preflate_recreate(&plain, &corrections)?)
        }
        other => Err(Error::Unsupported(format!("transformation {} ({other})", transform::name(other)))),
    }
}

/// The only PREFLATE correction format so far: preflate-rs 0.7.6 with the Archydes range coder
/// instead of CABAC (D-012). Every value ever written stays readable.
pub const PREFLATE_VER: &str = "preflate-rs-0.7.6/archydes-rc-1";

/// Largest plain text of one PREFLATE part.
const MAX_PREFLATE_PLAIN: usize = 1 << 30;

/// Rebuilds a raw deflate stream from plain text and PREFLATE corrections. A panic inside the
/// reconstruction (hostile corrections) is turned into an error.
pub fn preflate_recreate(plain: &[u8], corrections: &[u8]) -> Result<Vec<u8>> {
    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        preflate_rs::recreate_whole_deflate_stream(plain, corrections)
    }));
    match r {
        Ok(Ok(v)) => Ok(v),
        Ok(Err(e)) => Err(corrupt(format!("PREFLATE: {e:?}"))),
        Err(_) => Err(corrupt("PREFLATE: reconstruction failed")),
    }
}

/// The params map for a PREFLATE part.
pub fn preflate_part_params() -> Vec<(Value, Value)> {
    vec![(Value::text("ver"), Value::text(PREFLATE_VER)), (Value::text("wbits"), Value::int(-15))]
}

/// Largest JPEG XL input for JPEG_FROM_JXL.
const MAX_JXL: usize = 512 << 20;

/// Rebuilds the original JPEG from a JPEG XL file with reconstruction data (ISO/IEC 18181-2).
/// A panic inside jxl-oxide (seen with damaged input in jxl-jbr 0.2.1) counts as damage.
pub fn jpeg_from_jxl(jxl: &[u8], sink: &mut dyn FnMut(&[u8]) -> Result<()>) -> Result<()> {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| jpeg_from_jxl_inner(jxl, sink)))
        .unwrap_or_else(|_| Err(corrupt("JPEG_FROM_JXL: reconstruction failed")))
}

fn jpeg_from_jxl_inner(jxl: &[u8], sink: &mut dyn FnMut(&[u8]) -> Result<()>) -> Result<()> {
    use jxl_oxide::{JpegReconstructionStatus, JxlImage};
    let image =
        JxlImage::builder().read(std::io::Cursor::new(jxl)).map_err(|e| corrupt(format!("JPEG_FROM_JXL: {e}")))?;
    if image.jpeg_reconstruction_status() != JpegReconstructionStatus::Available {
        return Err(corrupt("JPEG_FROM_JXL: no JPEG reconstruction data"));
    }
    struct Forward<'a> {
        sink: &'a mut dyn FnMut(&[u8]) -> Result<()>,
        failed: Option<Error>,
    }
    impl std::io::Write for Forward<'_> {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            match (self.sink)(buf) {
                Ok(()) => Ok(buf.len()),
                Err(e) => {
                    self.failed = Some(e);
                    Err(std::io::Error::other("sink"))
                }
            }
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut w = Forward { sink, failed: None };
    let r = image.reconstruct_jpeg(&mut w);
    if let Some(e) = w.failed {
        return Err(e);
    }
    r.map_err(|e| corrupt(format!("JPEG_FROM_JXL: {e}")))
}

/// The params map for a JPEG_FROM_JXL part; `enc` is informative.
pub fn jxl_part_params(encoder: &str) -> Vec<(Value, Value)> {
    vec![(Value::text("enc"), Value::text(encoder))]
}

/// Rebuilds a part whose inputs are in memory and compares the result with `expected`,
/// stopping at the first difference.
pub fn part_reproduces(part: &Part, inputs: &[&[u8]], expected: &[u8]) -> bool {
    let mut pos = 0usize;
    let ok =
        rebuild_part(part, &mut |k, s| inputs.get(k).ok_or_else(|| corrupt("input")).and_then(|d| s(d)), &mut |b| {
            if expected.get(pos..pos + b.len()) == Some(b) {
                pos += b.len();
                Ok(())
            } else {
                Err(corrupt("differs"))
            }
        });
    ok.is_ok() && pos == expected.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text() -> Vec<u8> {
        (0..5000).flat_map(|i| format!("<row r=\"{i}\"><c>{}</c></row>", i * 7 % 13).into_bytes()).collect()
    }

    fn part(transform: u64, params: Vec<(Value, Value)>, inputs: usize) -> Part {
        Part { transform, params, inputs: vec![vec![]; inputs] }
    }

    #[test]
    fn zlib_exact_round_trip_and_parameter_checks() {
        let data = text();
        let p = Params { wbits: -15, level: 6, memlevel: 8, strategy: 0 };
        let comp = archydes_zlib::deflate(&data, p).unwrap();
        let ok = part(transform::ZLIB_EXACT, zlib_part_params(p), 1);
        assert!(part_reproduces(&ok, &[&data], &comp));
        // Other level: other bytes, so the check fails.
        let other = part(transform::ZLIB_EXACT, zlib_part_params(Params { level: 1, ..p }), 1);
        assert!(!part_reproduces(&other, &[&data], &comp));
        // Unknown implementation is reported, not guessed.
        let mut foreign = zlib_part_params(p);
        foreign.retain(|(k, _)| k.as_text() != Some("impl"));
        foreign.push((Value::text("impl"), Value::text("zlib-ng-9")));
        let r = rebuild_part(&part(transform::ZLIB_EXACT, foreign, 1), &mut |_, s| s(&data), &mut |_| Ok(()));
        assert!(matches!(r, Err(Error::Unsupported(_))), "{r:?}");
        // Invalid parameters are corrupt, not a crash.
        let mut bad = zlib_part_params(p);
        bad.retain(|(k, _)| k.as_text() != Some("wbits"));
        bad.push((Value::text("wbits"), Value::int(99)));
        assert!(!part_reproduces(&part(transform::ZLIB_EXACT, bad, 1), &[&data], &comp));
    }

    #[test]
    fn preflate_round_trip() {
        let data = text();
        // Z_FILTERED: a stream the ZLIB_EXACT parameter search would not find.
        let comp = archydes_zlib::deflate(&data, Params { wbits: -15, level: 6, memlevel: 8, strategy: 1 }).unwrap();
        let config = preflate_rs::PreflateConfig {
            max_chain_length: 4096,
            plain_text_limit: 1 << 30,
            verify_compression: false,
        };
        let (r, plain) = preflate_rs::preflate_whole_deflate_stream(&comp, &config).unwrap();
        assert_eq!(plain.text(), &data[..]);
        let p = part(transform::PREFLATE, preflate_part_params(), 2);
        assert!(part_reproduces(&p, &[plain.text(), &r.corrections], &comp));
        // Seeds for fuzz target `transform`: [kind, a, b, split, inputs…].
        if let Some(dir) = std::env::var_os("ARCHYDES_FUZZ_SEEDS") {
            let n = plain.text().len().to_be_bytes();
            let mut seed = vec![1, n[5], n[6], n[7]];
            seed.extend(plain.text());
            seed.extend(&r.corrections);
            std::fs::write(std::path::Path::new(&dir).join("preflate"), seed).unwrap();
            std::fs::write(std::path::Path::new(&dir).join("zlib"), [&[0u8, 0, 7, 7][..], &data[..4000]].concat())
                .unwrap();
        }
        if let Some(dir) = std::env::var_os("ARCHYDES_WRITE_VECTORS") {
            std::fs::write(std::path::Path::new(&dir).join("preflate-filtered.corr"), &r.corrections).unwrap();
        }
        // Damaged corrections: an error or other bytes, never a panic.
        let mut broken = r.corrections.clone();
        for b in broken.iter_mut().step_by(3) {
            *b ^= 0x5a;
        }
        assert!(!part_reproduces(&p, &[plain.text(), &broken], &comp));
        // Another coder version is refused.
        let other = part(transform::PREFLATE, vec![(Value::text("ver"), Value::text("preflate-rs-0.6/cabac"))], 2);
        assert!(!part_reproduces(&other, &[plain.text(), &r.corrections], &comp));
    }

    #[test]
    fn garbage_jxl_is_an_error() {
        let p = part(transform::JPEG_FROM_JXL, jxl_part_params("test"), 1);
        assert!(!part_reproduces(&p, &[b"\xff\x0a not a codestream"], b"\xff\xd8"));
        assert!(!part_reproduces(&p, &[b""], b""));
    }
}
