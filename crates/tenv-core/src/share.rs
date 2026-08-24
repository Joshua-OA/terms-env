//! Share envelope: wraps a signed payload into either a passphrase-mode or
//! pubkey-mode armored blob.
//!
//! Binary frame (before armor):
//!   magic "TENV" ‖ ver u8 ‖ mode u8 ‖ [salt16 | eph_pk32] ‖ nonce24 ‖ ct ‖ crc32u32
//! The CRC covers everything before it. The plaintext is JSON [`SignedPayload`].

use crate::crypto::{self, CryptoError, DeviceKeys, KdfParams, Mode};
use crate::domain::EnvVar;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

pub const MAGIC: &[u8; 4] = b"TENV";
pub const FORMAT_VERSION: u8 = 1;

const MODE_PASSPHRASE: u8 = 1;
const MODE_PUBKEY: u8 = 2;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShareError {
    Malformed(String),
    WrongPassphrase,
    BadSignature,
    Expired { at: u64 },
}

impl fmt::Display for ShareError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ShareError::Malformed(m) => write!(f, "malformed share: {m}"),
            ShareError::WrongPassphrase => write!(f, "wrong passphrase for this share"),
            ShareError::BadSignature => write!(
                f,
                "sender signature does not match payload; the share was altered"
            ),
            ShareError::Expired { at } => write!(
                f,
                "this share expired at unix timestamp {at}; ask for a fresh one"
            ),
        }
    }
}

impl std::error::Error for ShareError {}

impl From<CryptoError> for ShareError {
    fn from(value: CryptoError) -> Self {
        match value {
            CryptoError::Decrypt => ShareError::WrongPassphrase,
            other => ShareError::Malformed(other.to_string()),
        }
    }
}

pub type Result<T> = std::result::Result<T, ShareError>;

/// The authenticated plaintext inside every share envelope.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SignedPayload {
    pub version: u32,
    pub project: String,
    pub created_at: u64,
    pub expires_at: Option<u64>,
    pub vars: Vec<EnvVar>,
    /// Ed25519 public key of the sender's device identity.
    pub sender_pub: [u8; 32],
    /// Ed25519 signature over `signing_bytes` of the payload.
    #[serde(default)]
    pub signature: Vec<u8>,
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after epoch")
        .as_secs()
}

/// Canonical bytes covered by the signature: everything except the
/// signature itself.
fn signing_bytes(payload: &SignedPayload) -> Vec<u8> {
    let bare = SignedPayload {
        signature: Vec::new(),
        ..payload.clone()
    };
    serde_json::to_vec(&bare).expect("serialize canonical payload")
}

fn signed(payload: &mut SignedPayload, keys: &DeviceKeys) {
    payload.signature = keys.sign(&signing_bytes(payload)).to_bytes().to_vec();
}

/// Build and sign a payload without wrapping it in an envelope — used by the
/// live transport, which encrypts with the session key instead.
pub fn build_payload(
    project: &str,
    file: &crate::domain::EnvFile,
    keys: &DeviceKeys,
    ttl_secs: Option<u64>,
) -> SignedPayload {
    let mut payload = SignedPayload {
        version: u32::from(FORMAT_VERSION),
        project: project.to_string(),
        created_at: now_unix(),
        expires_at: ttl_secs.map(|t| now_unix() + t),
        vars: file.iter().cloned().collect(),
        sender_pub: keys.verifying_key().as_bytes().to_owned(),
        signature: Vec::new(),
    };
    signed(&mut payload, keys);
    payload
}

/// Wire bytes for a live transfer (full struct including signature).
pub fn payload_bytes(payload: &SignedPayload) -> Vec<u8> {
    serde_json::to_vec(payload).expect("serialize payload")
}

/// Validate signature + expiry on raw payload bytes (live or blob path).
pub fn verify_payload(bytes: &[u8]) -> Result<SignedPayload> {
    let mut payload: SignedPayload = serde_json::from_slice(bytes)
        .map_err(|e| ShareError::Malformed(format!("payload json: {e}")))?;
    if payload.version != u32::from(FORMAT_VERSION) {
        return Err(ShareError::Malformed(format!(
            "version {}",
            payload.version
        )));
    }

    let signature = std::mem::take(&mut payload.signature);
    let ok = crypto::verify(
        &ed25519_pub(&payload.sender_pub)?,
        &signing_bytes(&payload),
        &ed25519_sig(&signature)?,
    );
    if !ok {
        return Err(ShareError::BadSignature);
    }
    payload.signature = signature;

    if payload.expires_at.is_some_and(|t| now_unix() >= t) {
        return Err(ShareError::Expired {
            at: payload.expires_at.expect("checked above"),
        });
    }
    Ok(payload)
}

fn ed25519_pub(bytes: &[u8; 32]) -> Result<ed25519_dalek::VerifyingKey> {
    ed25519_dalek::VerifyingKey::from_bytes(bytes).map_err(|_| ShareError::BadSignature)
}

fn ed25519_sig(bytes: &[u8]) -> Result<ed25519_dalek::Signature> {
    let arr: [u8; 64] = bytes
        .try_into()
        .map_err(|_| ShareError::Malformed("signature length".into()))?;
    Ok(ed25519_dalek::Signature::from_bytes(&arr))
}

fn frame(mode: u8, material: &[u8], nonce: &[u8; crypto::NONCE_LEN], ct: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(6 + material.len() + nonce.len() + ct.len() + 4);
    out.extend_from_slice(MAGIC);
    out.push(FORMAT_VERSION);
    out.push(mode);
    out.extend_from_slice(material);
    out.extend_from_slice(nonce);
    out.extend_from_slice(ct);
    let crc = crc32fast::hash(&out);
    out.extend_from_slice(&crc.to_be_bytes());
    out
}

fn unframe(text: &str) -> Result<(Mode, Vec<u8>)> {
    let (mode, body) = crypto::dearmor(text).map_err(|e| ShareError::Malformed(e.to_string()))?;
    if body.len() < 14 || &body[..4] != MAGIC {
        return Err(ShareError::Malformed("bad magic".into()));
    }
    if body[4] != FORMAT_VERSION {
        return Err(ShareError::Malformed(format!("version {}", body[4])));
    }
    let expected_mode = match mode {
        Mode::Passphrase => MODE_PASSPHRASE,
        Mode::Pubkey => MODE_PUBKEY,
    };
    if body[5] != expected_mode {
        return Err(ShareError::Malformed("mode byte mismatch".into()));
    }

    let (frame_body, crc_bytes) = body.split_at(body.len() - 4);
    let stored_crc = u32::from_be_bytes(crc_bytes.try_into().expect("split guarantees 4"));
    if crc32fast::hash(frame_body) != stored_crc {
        return Err(ShareError::Malformed("checksum mismatch".into()));
    }
    Ok((mode, frame_body[6..].to_vec()))
}

/// Build a passphrase-mode armored share.
pub fn build_passphrase(
    project: &str,
    file: &crate::domain::EnvFile,
    keys: &DeviceKeys,
    ttl_secs: Option<u64>,
    passphrase: &str,
) -> Result<String> {
    let salt = crypto::random_salt();
    let key = crypto::derive_key(passphrase.as_bytes(), &salt, KdfParams::PRODUCTION);

    let payload = build_payload(project, file, keys, ttl_secs);
    let plaintext = serde_json::to_vec(&payload).expect("serialize payload");

    let nonce = crypto::random_nonce();
    let ct = crypto::seal(&key, &nonce, &plaintext);
    let frame = frame(MODE_PASSPHRASE, &salt, &nonce, &ct);
    Ok(crypto::armor(Mode::Passphrase, &frame))
}

/// Build a pubkey-mode armored share (sealed box to the recipient).
pub fn build_for_peer(
    project: &str,
    file: &crate::domain::EnvFile,
    keys: &DeviceKeys,
    ttl_secs: Option<u64>,
    peer_x25519_pub: &[u8; 32],
) -> Result<String> {
    let payload = build_payload(project, file, keys, ttl_secs);
    let plaintext = serde_json::to_vec(&payload).expect("serialize payload");

    let sealed = crypto::kex::seal(peer_x25519_pub, &plaintext);
    if sealed.len() < 32 + crypto::NONCE_LEN + crypto::TAG_LEN {
        return Err(ShareError::Malformed("sealed box too short".into()));
    }
    let material: [u8; 32] = sealed[..32].try_into().expect("checked length");
    let nonce: [u8; crypto::NONCE_LEN] = sealed[32..32 + crypto::NONCE_LEN]
        .try_into()
        .expect("checked length");
    let ct = &sealed[32 + crypto::NONCE_LEN..];
    let frame = frame(MODE_PUBKEY, &material, &nonce, ct);
    Ok(crypto::armor(Mode::Pubkey, &frame))
}

/// Open an armored blob. Supply exactly one of `passphrase` or
/// `my_x25519_sk` matching the blob's mode.
pub fn open_blob(
    text: &str,
    passphrase: Option<&str>,
    my_x25519_sk: Option<&[u8; 32]>,
) -> Result<SignedPayload> {
    let (mode, material) = unframe(text)?;

    let split_at = match mode {
        Mode::Passphrase => crypto::kdf::SALT_LEN,
        Mode::Pubkey => 32,
    };
    if material.len() < split_at + crypto::NONCE_LEN + crypto::TAG_LEN {
        return Err(ShareError::Malformed("frame too short".into()));
    }
    let key_material = &material[..split_at];
    let nonce: [u8; crypto::NONCE_LEN] = material[split_at..split_at + crypto::NONCE_LEN]
        .try_into()
        .expect("checked length");
    let ciphertext = &material[split_at + crypto::NONCE_LEN..];

    let plaintext = match mode {
        Mode::Passphrase => {
            let pass = passphrase.ok_or(ShareError::WrongPassphrase)?;
            let salt: [u8; crypto::kdf::SALT_LEN] =
                key_material.try_into().expect("checked length");
            let key = crypto::derive_key(pass.as_bytes(), &salt, KdfParams::PRODUCTION);
            crypto::open(&key, &nonce, ciphertext)?
        }
        Mode::Pubkey => {
            let sk =
                my_x25519_sk.ok_or(ShareError::Malformed("recipient secret required".into()))?;
            let eph_pk: [u8; 32] = key_material.try_into().expect("checked length");
            let shared = x25519_shared(sk, &eph_pk)?;
            let key = crypto::kdf::hkdf_sha256(&shared, "tenv/sealed-box/v1");
            crypto::open(&key, &nonce, ciphertext)?
        }
    };

    let mut plaintext = plaintext;
    let payload = verify_payload(&plaintext);
    use zeroize::Zeroize as _;
    plaintext.zeroize();
    payload
}

fn x25519_shared(sk: &[u8; 32], peer_pk: &[u8; 32]) -> Result<[u8; 32]> {
    use x25519_dalek::{PublicKey, StaticSecret};
    let secret = StaticSecret::from(*sk);
    let shared = secret.diffie_hellman(&PublicKey::from(*peer_pk));
    let mut out = [0u8; 32];
    out.copy_from_slice(shared.as_bytes());
    Ok(out)
}
