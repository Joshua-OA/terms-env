//! X25519 sealed boxes: encrypt to a recipient public key with an ephemeral
//! sender keypair (libsodium-style). Sender anonymity; only the recipient
//! can open.

use rand_core::{OsRng, RngCore};
use x25519_dalek::{PublicKey, StaticSecret};

use super::{CryptoError, Result, aead, kdf::hkdf_sha256};

const INFO: &str = "tenv/sealed-box/v1";
const PK_LEN: usize = 32;

/// Derive the public key matching a secret key.
pub fn public_key(secret: &[u8; 32]) -> [u8; 32] {
    let secret = StaticSecret::from(*secret);
    *PublicKey::from(&secret).as_bytes()
}

/// Layout: ephemeral_pk[32] ‖ nonce[24] ‖ ciphertext‖tag[16]
pub fn seal(recipient_pk: &[u8; 32], plaintext: &[u8]) -> Vec<u8> {
    let eph_secret = StaticSecret::random_from_rng(OsRng);
    let shared = eph_secret.diffie_hellman(&PublicKey::from(*recipient_pk));
    let key = hkdf_sha256(shared.as_bytes(), INFO);

    let mut nonce = [0u8; aead::NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);
    let ciphertext = aead::seal(&key, &nonce, plaintext);

    let mut out = Vec::with_capacity(PK_LEN + aead::NONCE_LEN + ciphertext.len());
    out.extend_from_slice(PublicKey::from(&eph_secret).as_bytes());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    out
}

pub fn open(recipient_sk: &[u8; 32], blob: &[u8]) -> Result<Vec<u8>> {
    let header = PK_LEN + aead::NONCE_LEN + aead::TAG_LEN;
    if blob.len() < header {
        return Err(CryptoError::Decrypt);
    }

    let (eph_pk, rest) = blob.split_at(PK_LEN);
    let eph_public = PublicKey::from(<[u8; 32]>::try_from(eph_pk).expect("checked length"));

    let secret = StaticSecret::from(*recipient_sk);
    let shared = secret.diffie_hellman(&eph_public);
    let key = hkdf_sha256(shared.as_bytes(), INFO);

    let (nonce, ciphertext) = rest.split_at(aead::NONCE_LEN);
    aead::open(
        &key,
        <&[u8; aead::NONCE_LEN]>::try_from(nonce).expect("checked length"),
        ciphertext,
    )
}
