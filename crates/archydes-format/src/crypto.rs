//! Encryption (SPEC A11, D-049 to D-055): KEY_INFO, key derivation, sealed segments and keyed
//! chunk IDs.
//!
//! The password only ever produces the key-encryption key (Argon2id). It unwraps a random data
//! key (DEK) stored in KEY_INFO; the segment key and the chunk-ID key are derived from the DEK
//! with BLAKE3 in key-derivation mode. Segments are sealed with XChaCha20-Poly1305 and a random
//! 24-byte nonce each.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use unicode_normalization::UnicodeNormalization;
use zeroize::{Zeroize, Zeroizing};

use crate::cbor::{self, Value};
use crate::consts::segment_type;
use crate::error::{Error, Result, corrupt};

pub const KEY_INFO_VERSION: u64 = 1;
pub const KDF_ARGON2ID: &str = "argon2id-1.3";
pub const AEAD_XCHACHA: &str = "xchacha20-poly1305";

pub const SALT_LEN: usize = 16;
pub const NONCE_LEN: usize = 24;
pub const TAG_LEN: usize = 16;
pub const KEY_LEN: usize = 32;
/// Nonce and tag around every sealed payload.
pub const OVERHEAD: usize = NONCE_LEN + TAG_LEN;

const KEY_AAD: &[u8] = b"archydes key v1";
const SEGMENT_AAD: &[u8] = b"archydes segment v1";
const SEGMENT_CONTEXT: &str = "archydes 2026-11 segment v1";
const CHUNK_CONTEXT: &str = "archydes 2026-11 chunk-id v1";

/// Argon2id parameters (D-050, D-052).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfParams {
    /// Memory in KiB.
    pub m: u32,
    /// Passes.
    pub t: u32,
    /// Lanes.
    pub p: u32,
}

impl KdfParams {
    /// What a packer writes by default: 256 MiB, 3 passes, 4 lanes (D-050).
    pub const DEFAULT: KdfParams = KdfParams { m: 256 * 1024, t: 3, p: 4 };
    /// The smallest a decoder accepts; for tests and test vectors only.
    pub const MINIMUM: KdfParams = KdfParams { m: 8 * 1024, t: 1, p: 1 };

    /// The decoder's limits (D-052): a hostile archive must not make it allocate more than
    /// 4 GiB or compute for hours, and weak parameters are rejected rather than used.
    pub fn check(&self) -> Result<()> {
        let ok = (8 * 1024..=4 * 1024 * 1024).contains(&self.m)
            && (1..=64).contains(&self.t)
            && (1..=64).contains(&self.p)
            && self.m >= 8 * self.p;
        if ok {
            Ok(())
        } else {
            Err(corrupt(format!(
                "key derivation parameters out of range (m={} KiB, t={}, p={})",
                self.m, self.t, self.p
            )))
        }
    }
}

/// Which AAD class a segment type is sealed under; `None` for segments that stay plaintext.
pub fn segment_class(kind: u16) -> Option<u8> {
    match kind {
        segment_type::PACK => Some(1),
        segment_type::INDEX | segment_type::INDEX_COPY => Some(2),
        _ => None,
    }
}

/// The decoded KEY_INFO segment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyInfo {
    pub params: KdfParams,
    pub salt: [u8; SALT_LEN],
    pub nonce: [u8; NONCE_LEN],
    /// The DEK sealed under the KEK, tag at the end.
    pub wrapped: [u8; KEY_LEN + TAG_LEN],
}

impl KeyInfo {
    fn fields(&self) -> Vec<(&'static str, Value)> {
        vec![
            ("v", Value::Uint(KEY_INFO_VERSION)),
            ("kdf", Value::text(KDF_ARGON2ID)),
            ("m", Value::Uint(self.params.m.into())),
            ("t", Value::Uint(self.params.t.into())),
            ("p", Value::Uint(self.params.p.into())),
            ("salt", Value::Bytes(self.salt.to_vec())),
            ("aead", Value::text(AEAD_XCHACHA)),
        ]
    }

    fn map(fields: Vec<(&'static str, Value)>) -> Value {
        Value::Map(fields.into_iter().map(|(k, v)| (Value::text(k), v)).collect())
    }

    /// The KEY_INFO payload (deterministic CBOR).
    pub fn encode(&self) -> Vec<u8> {
        let mut fields = self.fields();
        fields.push(("nonce", Value::Bytes(self.nonce.to_vec())));
        fields.push(("wrapped", Value::Bytes(self.wrapped.to_vec())));
        cbor::encode(&Self::map(fields))
    }

    /// Checks version, algorithms, lengths and limits before anything is computed.
    pub fn decode(payload: &[u8]) -> Result<KeyInfo> {
        let value = cbor::decode(payload)?;
        let map = value.as_map().ok_or_else(|| corrupt("KEY_INFO is not a map"))?;
        const KEYS: [&str; 9] = ["v", "kdf", "m", "t", "p", "salt", "aead", "nonce", "wrapped"];
        for (k, _) in map {
            match k.as_text() {
                Some(name) if KEYS.contains(&name) => {}
                _ => return Err(corrupt("KEY_INFO has an unknown field")),
            }
        }
        if map.len() != KEYS.len() {
            return Err(corrupt("KEY_INFO fields missing or repeated"));
        }
        let uint = |k: &str| value.get(k).and_then(Value::as_u64).ok_or_else(|| corrupt(format!("KEY_INFO {k}")));
        let text = |k: &str| value.get(k).and_then(Value::as_text).ok_or_else(|| corrupt(format!("KEY_INFO {k}")));
        let bytes = |k: &str| value.get(k).and_then(Value::as_bytes).ok_or_else(|| corrupt(format!("KEY_INFO {k}")));
        let v = uint("v")?;
        if v != KEY_INFO_VERSION {
            return Err(Error::Unsupported(format!("KEY_INFO version {v}")));
        }
        let (kdf, aead) = (text("kdf")?, text("aead")?);
        if kdf != KDF_ARGON2ID {
            return Err(Error::Unsupported(format!("key derivation {kdf:?}")));
        }
        if aead != AEAD_XCHACHA {
            return Err(Error::Unsupported(format!("encryption {aead:?}")));
        }
        let small = |k: &str| -> Result<u32> { u32::try_from(uint(k)?).map_err(|_| corrupt(format!("KEY_INFO {k}"))) };
        let params = KdfParams { m: small("m")?, t: small("t")?, p: small("p")? };
        params.check()?;
        let fixed = |k: &str, len: usize| -> Result<&[u8]> {
            let b = bytes(k)?;
            if b.len() == len { Ok(b) } else { Err(corrupt(format!("KEY_INFO {k} has the wrong length"))) }
        };
        Ok(KeyInfo {
            params,
            salt: fixed("salt", SALT_LEN)?.try_into().unwrap(),
            nonce: fixed("nonce", NONCE_LEN)?.try_into().unwrap(),
            wrapped: fixed("wrapped", KEY_LEN + TAG_LEN)?.try_into().unwrap(),
        })
    }

    /// `"archydes key v1" ‖ uuid ‖ CBOR of the map without nonce and wrapped`.
    fn aad(&self, uuid: &[u8; 16]) -> Vec<u8> {
        let mut aad = Vec::with_capacity(96);
        aad.extend_from_slice(KEY_AAD);
        aad.extend_from_slice(uuid);
        cbor::encode_into(&Self::map(self.fields()), &mut aad);
        aad
    }

    /// Derives the KEK from the password and unwraps the DEK. A failing tag means the password
    /// is wrong (or KEY_INFO was altered, which a segment hash check before this rules out).
    pub fn unlock(&self, password: &str, uuid: &[u8; 16]) -> Result<Keys> {
        self.params.check()?;
        let kek = derive_kek(password, &self.salt, self.params)?;
        let cipher = XChaCha20Poly1305::new(&(*kek).into());
        let aad = self.aad(uuid);
        let dek = cipher
            .decrypt(&XNonce::from(self.nonce), Payload { msg: &self.wrapped, aad: &aad })
            .map_err(|_| Error::WrongPassword)?;
        let dek = Zeroizing::new(dek);
        let dek: [u8; KEY_LEN] = dek.as_slice().try_into().map_err(|_| corrupt("data key length"))?;
        Ok(Keys::from_dek(dek))
    }
}

/// Argon2id v1.3 over the password in Unicode NFC.
pub fn derive_kek(password: &str, salt: &[u8; SALT_LEN], params: KdfParams) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    let normalized: Zeroizing<String> = Zeroizing::new(password.nfc().collect());
    let argon_params = argon2::Params::new(params.m, params.t, params.p, Some(KEY_LEN))
        .map_err(|e| corrupt(format!("key derivation parameters: {e}")))?;
    let argon = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, argon_params);
    let mut kek = Zeroizing::new([0u8; KEY_LEN]);
    argon
        .hash_password_into(normalized.as_bytes(), salt, kek.as_mut())
        .map_err(|e| corrupt(format!("key derivation: {e}")))?;
    Ok(kek)
}

/// Random bytes from the operating system.
pub fn random<const N: usize>() -> Result<[u8; N]> {
    let mut b = [0u8; N];
    getrandom::fill(&mut b).map_err(|e| Error::Io(std::io::Error::other(format!("no random numbers: {e}"))))?;
    Ok(b)
}

/// The keys of an unlocked archive. Zeroed when dropped.
#[derive(Clone)]
pub struct Keys {
    segment: [u8; KEY_LEN],
    chunk: [u8; KEY_LEN],
}

impl Drop for Keys {
    fn drop(&mut self) {
        self.segment.zeroize();
        self.chunk.zeroize();
    }
}

impl std::fmt::Debug for Keys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Keys(…)")
    }
}

impl Keys {
    /// The subkeys of a data key (D-051).
    pub fn from_dek(mut dek: [u8; KEY_LEN]) -> Keys {
        let keys =
            Keys { segment: blake3::derive_key(SEGMENT_CONTEXT, &dek), chunk: blake3::derive_key(CHUNK_CONTEXT, &dek) };
        dek.zeroize();
        keys
    }

    /// New keys for a new archive: random salt, data key and nonce.
    pub fn create(password: &str, uuid: &[u8; 16], params: KdfParams) -> Result<(Keys, KeyInfo)> {
        let mut dek = random::<KEY_LEN>()?;
        let result = Self::create_with(password, uuid, params, random()?, &dek, random()?);
        dek.zeroize();
        result
    }

    /// Like [`Keys::create`] with given salt, data key and nonce, for test vectors.
    pub fn create_with(
        password: &str,
        uuid: &[u8; 16],
        params: KdfParams,
        salt: [u8; SALT_LEN],
        dek: &[u8; KEY_LEN],
        nonce: [u8; NONCE_LEN],
    ) -> Result<(Keys, KeyInfo)> {
        params.check()?;
        let kek = derive_kek(password, &salt, params)?;
        let mut info = KeyInfo { params, salt, nonce, wrapped: [0; KEY_LEN + TAG_LEN] };
        let aad = info.aad(uuid);
        let wrapped = XChaCha20Poly1305::new(&(*kek).into())
            .encrypt(&XNonce::from(nonce), Payload { msg: dek, aad: &aad })
            .map_err(|_| corrupt("wrapping the data key"))?;
        info.wrapped.copy_from_slice(&wrapped);
        Ok((Keys::from_dek(*dek), info))
    }

    fn segment_aad(uuid: &[u8; 16], class: u8) -> [u8; 36] {
        let mut aad = [0u8; 36];
        aad[..19].copy_from_slice(SEGMENT_AAD);
        aad[19..35].copy_from_slice(uuid);
        aad[35] = class;
        aad
    }

    /// `nonce ‖ ciphertext ‖ tag` of a segment payload, with a random nonce.
    pub fn seal(&self, uuid: &[u8; 16], class: u8, plaintext: &[u8]) -> Result<Vec<u8>> {
        self.seal_with_nonce(uuid, class, plaintext, random()?)
    }

    /// Like [`Keys::seal`] with a given nonce, for test vectors. A nonce must never be used twice.
    pub fn seal_with_nonce(
        &self,
        uuid: &[u8; 16],
        class: u8,
        plaintext: &[u8],
        nonce: [u8; NONCE_LEN],
    ) -> Result<Vec<u8>> {
        let aad = Self::segment_aad(uuid, class);
        let sealed = XChaCha20Poly1305::new(&self.segment.into())
            .encrypt(&XNonce::from(nonce), Payload { msg: plaintext, aad: &aad })
            .map_err(|_| corrupt("encrypting a segment"))?;
        let mut out = Vec::with_capacity(NONCE_LEN + sealed.len());
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&sealed);
        Ok(out)
    }

    /// The plaintext of a sealed segment payload; a failing tag is damage.
    pub fn open(&self, uuid: &[u8; 16], class: u8, stored: &[u8]) -> Result<Vec<u8>> {
        if stored.len() < OVERHEAD {
            return Err(corrupt("encrypted segment too short"));
        }
        let (nonce, sealed) = stored.split_at(NONCE_LEN);
        let aad = Self::segment_aad(uuid, class);
        XChaCha20Poly1305::new(&self.segment.into())
            .decrypt(&XNonce::from(<[u8; NONCE_LEN]>::try_from(nonce).unwrap()), Payload { msg: sealed, aad: &aad })
            .map_err(|_| corrupt("encrypted segment fails its authentication tag"))
    }

    /// Chunk ID: BLAKE3 keyed with `k_chunk`.
    pub fn chunk_id(&self, data: &[u8]) -> [u8; 32] {
        *blake3::keyed_hash(&self.chunk, data).as_bytes()
    }

    /// A hasher for chunk IDs of data that arrives in pieces.
    pub fn chunk_hasher(&self) -> blake3::Hasher {
        blake3::Hasher::new_keyed(&self.chunk)
    }
}

/// What a writer needs to encrypt: the keys, the archive UUID and the KEY_INFO payload that
/// every generation repeats.
#[derive(Debug, Clone)]
pub struct Encryption {
    pub keys: Keys,
    pub uuid: [u8; 16],
    pub key_info: Vec<u8>,
}

impl Encryption {
    pub fn new(keys: Keys, uuid: [u8; 16], info: &KeyInfo) -> Encryption {
        Encryption { keys, uuid, key_info: info.encode() }
    }

    /// The stored payload of a PACK segment: pack header and compressed data, sealed. For
    /// [`crate::ArchiveWriter::write_sealed_pack`], so packs can be sealed in parallel.
    pub fn seal_pack(&self, header: &crate::PackHeader, data: &[u8]) -> Result<Vec<u8>> {
        let mut plain = header.encode_prefix();
        plain.extend_from_slice(data);
        self.keys.seal(&self.uuid, 1, &plain)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const UUID: [u8; 16] = [9; 16];

    #[test]
    fn key_info_round_trip_and_unlock() {
        let (keys, info) = Keys::create("geheim", &UUID, KdfParams::MINIMUM).unwrap();
        let decoded = KeyInfo::decode(&info.encode()).unwrap();
        assert_eq!(decoded, info);
        let unlocked = decoded.unlock("geheim", &UUID).unwrap();
        assert_eq!(unlocked.chunk_id(b"abc"), keys.chunk_id(b"abc"));
        assert!(matches!(decoded.unlock("Geheim", &UUID), Err(Error::WrongPassword)));
        assert!(matches!(decoded.unlock("geheim", &[8; 16]), Err(Error::WrongPassword)));
    }

    #[test]
    fn password_is_normalized() {
        // "é" precomposed and as e + combining accent.
        let (_, info) = Keys::create("caf\u{e9}", &UUID, KdfParams::MINIMUM).unwrap();
        assert!(info.unlock("cafe\u{301}", &UUID).is_ok());
    }

    #[test]
    fn changed_parameters_fail_the_tag() {
        let (_, info) = Keys::create("pw", &UUID, KdfParams { m: 16 * 1024, t: 1, p: 1 }).unwrap();
        let mut weaker = info.clone();
        weaker.params.m = 8 * 1024;
        assert!(matches!(weaker.unlock("pw", &UUID), Err(Error::WrongPassword)));
    }

    #[test]
    fn limits_are_checked_before_computing() {
        for params in [
            KdfParams { m: 4096, t: 1, p: 1 },
            KdfParams { m: 8 * 1024 * 1024, t: 1, p: 1 },
            KdfParams { m: 8192, t: 0, p: 1 },
            KdfParams { m: 8192, t: 65, p: 1 },
            KdfParams { m: 8192, t: 1, p: 0 },
            KdfParams { m: 8192, t: 1, p: 1025 },
        ] {
            let info = KeyInfo { params, salt: [0; 16], nonce: [0; 24], wrapped: [0; 48] };
            assert!(matches!(KeyInfo::decode(&info.encode()), Err(Error::Corrupt(_))), "{params:?}");
            assert!(info.unlock("x", &UUID).is_err());
        }
    }

    #[test]
    fn key_info_rejects_unknown_things() {
        let info = KeyInfo { params: KdfParams::MINIMUM, salt: [1; 16], nonce: [2; 24], wrapped: [3; 48] };
        let mut fields = info.fields();
        fields.push(("nonce", Value::Bytes(vec![2; 24])));
        fields.push(("wrapped", Value::Bytes(vec![3; 48])));
        let with = |name: &str, v: Value| {
            let mut f: Vec<(&str, Value)> = fields.iter().filter(|(k, _)| *k != name).cloned().collect();
            f.push((if name == "extra" { "extra" } else { name }, v));
            cbor::encode(&Value::Map(f.into_iter().map(|(k, v)| (Value::text(k), v)).collect()))
        };
        assert!(KeyInfo::decode(&with("v", Value::Uint(2))).is_err());
        assert!(KeyInfo::decode(&with("kdf", Value::text("scrypt"))).is_err());
        assert!(KeyInfo::decode(&with("aead", Value::text("aes-256-gcm"))).is_err());
        assert!(KeyInfo::decode(&with("salt", Value::Bytes(vec![1; 15]))).is_err());
        assert!(KeyInfo::decode(&with("extra", Value::Null)).is_err());
        assert!(KeyInfo::decode(&with("nonce", Value::Bytes(vec![2; 24]))).is_ok());
        assert!(KeyInfo::decode(b"\xa0").is_err());
    }

    #[test]
    fn segments_are_bound_to_archive_and_class() {
        let keys = Keys::from_dek([5; 32]);
        let sealed = keys.seal(&UUID, 1, b"pack data").unwrap();
        assert_eq!(sealed.len(), 9 + OVERHEAD);
        assert_eq!(keys.open(&UUID, 1, &sealed).unwrap(), b"pack data");
        assert!(keys.open(&UUID, 2, &sealed).is_err());
        assert!(keys.open(&[0; 16], 1, &sealed).is_err());
        let mut flipped = sealed.clone();
        flipped[30] ^= 1;
        assert!(keys.open(&UUID, 1, &flipped).is_err());
        assert!(keys.open(&UUID, 1, &sealed[..20]).is_err());
        assert_ne!(keys.seal(&UUID, 1, b"pack data").unwrap(), sealed, "nonces are random");
    }

    #[test]
    fn chunk_ids_are_keyed() {
        let a = Keys::from_dek([1; 32]);
        let b = Keys::from_dek([2; 32]);
        assert_ne!(a.chunk_id(b"x"), b.chunk_id(b"x"));
        assert_ne!(a.chunk_id(b"x"), crate::hash256(b"x"));
        let mut h = a.chunk_hasher();
        h.update(b"x");
        assert_eq!(*h.finalize().as_bytes(), a.chunk_id(b"x"));
    }
}
