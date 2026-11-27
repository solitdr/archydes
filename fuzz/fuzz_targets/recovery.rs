#![no_main]
//! Recovery data in hostile archives: find it, check every slice, never trust a length.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let bytes = data.to_vec();
    if let Some(layout) = archydes_recovery::locate(&bytes) {
        let _ = archydes_recovery::check(&bytes, &layout, 1);
    }
});
