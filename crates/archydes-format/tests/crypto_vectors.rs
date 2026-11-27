//! Known-answer vectors for SPEC A11: Argon2id, wrapping the data key, the subkeys, sealing a
//! segment and keyed chunk IDs. They fix the meaning of the format: a failing vector is a
//! format break, not a test to update. All values were checked against independent
//! implementations (libargon2 via argon2-cffi, libsodium via PyNaCl, the BLAKE3 reference),
//! with the wrap AAD built by hand from the specification.

use archydes_format::crypto::{KdfParams, KeyInfo, Keys, derive_kek};

fn seq<const N: usize>(start: u8) -> [u8; N] {
    std::array::from_fn(|i| start.wrapping_add(i as u8))
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

const UUID: [u8; 16] = *b"archydes-vector2";
const PARAMS: KdfParams = KdfParams { m: 8192, t: 1, p: 1 };

#[test]
fn key_derivation_and_wrapping() {
    let salt = seq::<16>(0x00);
    let dek = seq::<32>(0x20);
    let nonce = seq::<24>(0x40);
    // NFC and NFD spellings derive the same key.
    let kek = derive_kek("Pr\u{fc}fung", &salt, PARAMS).unwrap();
    assert_eq!(*kek, *derive_kek("Pru\u{308}fung", &salt, PARAMS).unwrap());
    assert_eq!(hex(&*kek), "62f0a05d784def58efa7b146914a2ec7e49ef443c2aeaa30167026294da148ce");
    let (keys, info) = Keys::create_with("Pr\u{fc}fung", &UUID, PARAMS, salt, &dek, nonce).unwrap();
    assert_eq!(
        hex(&info.wrapped),
        "e867c453d0220e0072fcd25dbf84e85ef753542b101598352850791f581a419914781100816a34d241e115ce71c3f8de"
    );
    assert_eq!(
        hex(&info.encode()),
        concat!(
            "a9616d192000617001617401617601636b64666c6172676f6e3269642d312e336461656164727863686163686132302d",
            "706f6c79313330356473616c7450000102030405060708090a0b0c0d0e0f656e6f6e63655818404142434445464748",
            "494a4b4c4d4e4f505152535455565767777261707065645830e867c453d0220e0072fcd25dbf84e85ef753542b1015",
            "98352850791f581a419914781100816a34d241e115ce71c3f8de"
        )
    );
    // Keyed chunk ID of "Archydes".
    assert_eq!(hex(&keys.chunk_id(b"Archydes")), "d163cbb40cfa34827b3cffdc540970307a5c70ed2182cbb7e32e9bb767759d28");
    // "Archydes" sealed as a PACK payload (class 1) with nonce 60 61 … 77.
    let sealed = keys.seal_with_nonce(&UUID, 1, b"Archydes", seq::<24>(0x60)).unwrap();
    assert_eq!(
        hex(&sealed),
        "606162636465666768696a6b6c6d6e6f7071727374757677f23887d8dd818a00689bb3106642e0d620613e1d72b56009"
    );
    let unlocked = KeyInfo::decode(&info.encode()).unwrap().unlock("Pru\u{308}fung", &UUID).unwrap();
    assert_eq!(unlocked.open(&UUID, 1, &sealed).unwrap(), b"Archydes");
}

/// `cargo test --release -p archydes-format --test crypto_vectors -- --ignored --nocapture timing`
/// measures Argon2 with the default parameters (target 0.5 to 1 s, D-050).
#[test]
#[ignore]
fn timing() {
    for params in [KdfParams::DEFAULT, KdfParams { m: 128 * 1024, t: 3, p: 4 }, KdfParams { m: 512 * 1024, t: 3, p: 4 }]
    {
        let start = std::time::Instant::now();
        derive_kek("timing", &[0; 16], params).unwrap();
        println!("m={} MiB t={} p={}: {:.2} s", params.m / 1024, params.t, params.p, start.elapsed().as_secs_f64());
    }
}
