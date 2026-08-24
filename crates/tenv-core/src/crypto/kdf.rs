//! Key derivation: Argon2id for human passphrases, HKDF-SHA256 for raw secrets.

use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

pub const SALT_LEN: usize = 16;
pub const KEY_LEN: usize = 32;

#[derive(Clone, Copy, Debug)]
pub struct KdfParams {
    pub m_kib: u32,
    pub t: u32,
    pub p: u32,
}

impl KdfParams {
    pub const PRODUCTION: Self = Self {
        m_kib: 64 * 1024,
        t: 3,
        p: 1,
    };
    pub const TEST: Self = Self {
        m_kib: 8 * 1024,
        t: 1,
        p: 1,
    };
}

pub fn random_salt() -> [u8; SALT_LEN] {
    let mut salt = [0u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt);
    salt
}

pub fn derive_key(
    passphrase: &[u8],
    salt: &[u8; SALT_LEN],
    params: KdfParams,
) -> Zeroizing<[u8; KEY_LEN]> {
    let argon = Argon2::new(
        Algorithm::Argon2id,
        Version::V0x13,
        Params::new(params.m_kib, params.t, params.p, Some(KEY_LEN)).expect("valid params"),
    );
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    argon
        .hash_password_into(passphrase, salt, key.as_mut())
        .expect("argon2 hash into fixed buffer");
    key
}

pub fn hkdf_sha256(ikm: &[u8], info: &str) -> Zeroizing<[u8; KEY_LEN]> {
    let hk = Hkdf::<Sha256>::new(None, ikm);
    let mut okm = Zeroizing::new([0u8; KEY_LEN]);
    hk.expand(info.as_bytes(), okm.as_mut())
        .expect("32-byte expansion always valid");
    okm
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}
