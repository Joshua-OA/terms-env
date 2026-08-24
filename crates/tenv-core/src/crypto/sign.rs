//! Ed25519 device identity: key generation, signatures, display fingerprints.
//! The fingerprint (SHA-256 of the public key, hex-grouped) is what humans
//! compare out-of-band to defeat man-in-the-middle key swaps.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand_core::OsRng;

use super::kdf::sha256;

pub struct DeviceKeys {
    signing: SigningKey,
}

impl DeviceKeys {
    pub fn generate() -> Self {
        Self {
            signing: SigningKey::generate(&mut OsRng),
        }
    }

    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self {
            signing: SigningKey::from_bytes(seed),
        }
    }

    pub fn to_seed(&self) -> [u8; 32] {
        self.signing.to_bytes()
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing.verifying_key()
    }

    pub fn sign(&self, message: &[u8]) -> Signature {
        self.signing.sign(message)
    }
}

/// `XXXX-XXXX-XXXX-XXXX` from the first 16 hex chars of SHA-256(public key).
pub fn fingerprint(key: &VerifyingKey) -> String {
    let digest = sha256(key.as_bytes());
    let mut out = String::with_capacity(19);
    for (i, byte) in digest[..8].iter().enumerate() {
        if i > 0 && i % 2 == 0 {
            out.push('-');
        }
        out.push_str(&format!("{byte:02X}"));
    }
    out
}

pub fn verify(key: &VerifyingKey, message: &[u8], signature: &Signature) -> bool {
    key.verify(message, signature).is_ok()
}
