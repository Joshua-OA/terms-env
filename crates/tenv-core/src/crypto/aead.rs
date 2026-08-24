//! XChaCha20-Poly1305 AEAD: one-shot helpers plus a counter-nonce chunk
//! stream. Stream layout: 24-byte nonce = 20 random prefix bytes +
//! big-endian u32 chunk counter, so chunks only decrypt in order.

use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use rand_core::{OsRng, RngCore};

use super::CryptoError;

pub const NONCE_LEN: usize = 24;
pub const TAG_LEN: usize = 16;

pub fn random_nonce() -> [u8; NONCE_LEN] {
    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);
    nonce
}

fn cipher(key: &[u8; 32]) -> XChaCha20Poly1305 {
    XChaCha20Poly1305::new(key.into())
}

pub fn seal(key: &[u8; 32], nonce: &[u8; NONCE_LEN], plaintext: &[u8]) -> Vec<u8> {
    cipher(key)
        .encrypt(XNonce::from_slice(nonce), Payload::from(plaintext))
        .expect("AEAD encryption is infallible for valid inputs")
}

pub fn open(
    key: &[u8; 32],
    nonce: &[u8; NONCE_LEN],
    ciphertext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    cipher(key)
        .decrypt(XNonce::from_slice(nonce), Payload::from(ciphertext))
        .map_err(|_| CryptoError::Decrypt)
}

fn nonce_for(prefix: &[u8; 20], counter: u32) -> [u8; NONCE_LEN] {
    let mut nonce = [0u8; NONCE_LEN];
    nonce[..20].copy_from_slice(prefix);
    nonce[20..].copy_from_slice(&counter.to_be_bytes());
    nonce
}

/// Both peers independently derive the same 20-byte prefix from the shared
/// key, so no prefix ever needs to travel over the wire.
fn stream_prefix(key: &[u8; 32]) -> [u8; 20] {
    let derived = super::kdf::hkdf_sha256(key, "tenv/stream-nonce/v1");
    let mut prefix = [0u8; 20];
    prefix.copy_from_slice(&derived[..20]);
    prefix
}

pub struct StreamSeal {
    key: [u8; 32],
    prefix: [u8; 20],
    counter: u32,
}

impl StreamSeal {
    pub fn new(key: [u8; 32]) -> Self {
        Self {
            prefix: stream_prefix(&key),
            key,
            counter: 0,
        }
    }

    pub fn seal_chunk(&mut self, plaintext: &[u8]) -> Vec<u8> {
        let nonce = nonce_for(&self.prefix, self.counter);
        self.counter += 1;
        seal(&self.key, &nonce, plaintext)
    }
}

pub struct StreamOpen {
    key: [u8; 32],
    prefix: [u8; 20],
    counter: u32,
}

impl StreamOpen {
    pub fn new(key: [u8; 32]) -> Self {
        Self {
            key,
            prefix: stream_prefix(&key),
            counter: 0,
        }
    }

    pub fn open_chunk(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let nonce = nonce_for(&self.prefix, self.counter);
        self.counter += 1;
        open(&self.key, &nonce, ciphertext)
    }
}
