//! Crypto engine: SPAKE2 handshake, XChaCha20-Poly1305 AEAD, Argon2id KDF,
//! Ed25519 signatures, X25519 sealed boxes, armor codec.

mod aead;
mod armor;
pub mod kdf;
pub mod kex;
pub mod sign;
pub mod spake;

pub use aead::{NONCE_LEN, StreamOpen, StreamSeal, TAG_LEN, open, random_nonce, seal};
pub use armor::{Mode, armor, dearmor};
pub use kdf::{KdfParams, derive_key, random_salt};
pub use sign::{DeviceKeys, fingerprint, verify};

use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CryptoError {
    Decrypt,
    Handshake,
    MalformedArmor(String),
    BadKeyLength { expected: usize, got: usize },
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CryptoError::Decrypt => write!(f, "decryption failed (wrong key or tampered data)"),
            CryptoError::Handshake => write!(f, "handshake failed"),
            CryptoError::MalformedArmor(detail) => write!(f, "malformed armored input: {detail}"),
            CryptoError::BadKeyLength { expected, got } => {
                write!(f, "bad key length: expected {expected}, got {got}")
            }
        }
    }
}

impl std::error::Error for CryptoError {}

pub type Result<T> = std::result::Result<T, CryptoError>;
