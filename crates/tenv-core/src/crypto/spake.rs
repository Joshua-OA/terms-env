//! SPAKE2 (RFC 9382) session wrapper over the Ed25519 group.
//! Both sides feed in the same low-entropy code and derive the same
//! high-entropy session key. An active attacker gets exactly one guess.

use spake2::{Ed25519Group, Identity, Password, Spake2};
use zeroize::Zeroizing;

use super::Result;
use super::kdf::KEY_LEN;

const SHARED_IDENTITY: &str = "terms-env";

pub struct Session {
    inner: Spake2<Ed25519Group>,
}

/// Returns the local protocol message to send to the peer.
pub fn begin(password: &[u8]) -> Result<(Session, Vec<u8>)> {
    let (state, message) = Spake2::<Ed25519Group>::start_symmetric(
        &Password::new(password),
        &Identity::new(SHARED_IDENTITY.as_bytes()),
    );
    Ok((Session { inner: state }, message))
}

impl Session {
    /// Consumes the peer's message and derives the shared session key.
    pub fn finish(self, peer_message: &[u8]) -> Result<Zeroizing<[u8; KEY_LEN]>> {
        let shared = self
            .inner
            .finish(peer_message)
            .map_err(|_| super::CryptoError::Handshake)?;
        let mut key = Zeroizing::new([0u8; KEY_LEN]);
        key.copy_from_slice(&shared[..KEY_LEN]);
        Ok(key)
    }
}
