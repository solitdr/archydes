#![no_main]
//! CBOR decoder; decoded values must re-encode and decode to the same value.
use archydes_format::cbor;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(v) = cbor::decode(data) {
        let again = cbor::decode(&cbor::encode(&v)).expect("re-encoded value must decode");
        assert_eq!(cbor::encode(&again), cbor::encode(&v));
    }
});
