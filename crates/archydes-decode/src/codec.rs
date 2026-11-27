//! Decompression of packs (codec registry, SPEC A5.3).

use archydes_format::consts::{codec, limits};
use archydes_format::{Error, PackHeader, Result, corrupt};

/// Decompresses one pack; the result has exactly `header.ulen` bytes.
pub fn decompress(header: &PackHeader, data: Vec<u8>) -> Result<Vec<u8>> {
    let ulen = header.ulen as usize;
    let out = match header.codec {
        codec::NONE => data,
        codec::ZSTD => zstd::bulk::decompress(&data, ulen).map_err(|e| corrupt(format!("zstd: {e}")))?,
        codec::LZMA2 => lzma2(&data, header)?,
        other => return Err(Error::Unsupported(format!("codec {other}"))),
    };
    if out.len() != ulen {
        return Err(corrupt(format!("pack decompressed to {} bytes instead of {ulen}", out.len())));
    }
    Ok(out)
}

fn lzma2(data: &[u8], header: &PackHeader) -> Result<Vec<u8>> {
    use liblzma::stream::{Action, Filters, LzmaOptions, Status, Stream};

    let dict = header.dict.ok_or_else(|| corrupt("LZMA2 pack without dictionary size"))?;
    if !(4096..=limits::MAX_LZMA2_DICT).contains(&dict) {
        return Err(Error::Limit(format!("LZMA2 dictionary of {dict} bytes")));
    }
    let mut opts = LzmaOptions::new_preset(6).map_err(|e| corrupt(format!("LZMA2: {e}")))?;
    opts.dict_size(dict as u32);
    let mut filters = Filters::new();
    filters.lzma2(&opts);
    let mut stream = Stream::new_raw_decoder(&filters).map_err(|e| corrupt(format!("LZMA2: {e}")))?;

    // One byte more than declared, so too much output is detected instead of truncated.
    let mut out = Vec::with_capacity(header.ulen as usize + 1);
    loop {
        let (before_in, before_out) = (stream.total_in(), stream.total_out());
        let input = &data[stream.total_in() as usize..];
        let status = stream.process_vec(input, &mut out, Action::Finish).map_err(|e| corrupt(format!("LZMA2: {e}")))?;
        if out.len() as u64 > header.ulen {
            return Err(corrupt("LZMA2 pack holds more data than declared"));
        }
        if matches!(status, Status::StreamEnd) {
            break;
        }
        if stream.total_in() == before_in && stream.total_out() == before_out {
            return Err(corrupt("LZMA2 data truncated"));
        }
    }
    if stream.total_in() as usize != data.len() {
        return Err(corrupt("LZMA2 pack has trailing data"));
    }
    Ok(out)
}
