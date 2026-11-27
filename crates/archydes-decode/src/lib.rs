//! Reading, extracting and verifying Archydes archives.
//!
//! Everything needed to get files out of an archive is here and open (`MIT OR Apache-2.0`):
//! decompression of all codecs, the reverse direction of all transformations, extraction with
//! metadata and verification.

pub mod codec;
pub mod extract;
mod meta;
pub mod path;
pub mod reader;
pub mod transform;
pub mod verify;

pub use archydes_format::{Error, Result};
pub use extract::{ExtractOptions, ExtractReport, Progress, extract, extract_mapped};
pub use reader::Reader;
pub use verify::{VerifyReport, verify};
