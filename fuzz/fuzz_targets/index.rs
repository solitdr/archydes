#![no_main]
//! Index from raw CBOR (without zstd, so the fuzzer reaches the validation).
use archydes_format::{Index, cbor};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(v) = cbor::decode(data) {
        if let Ok(index) = Index::from_value(&v) {
            // A valid index must survive a round trip.
            assert_eq!(Index::from_value(&index.to_value()).unwrap(), index);
        }
    }
});
