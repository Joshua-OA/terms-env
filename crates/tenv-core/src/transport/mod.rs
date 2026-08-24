//! Transport: iroh-based live handoff (direct QUIC first, relay fallback
//! handled by iroh itself) plus code-string encoding.
//!
//! Wire protocol on ALPN `tenv/share/1`, one bidirectional stream:
//!   receiver → sender : SPAKE2 message (framed)
//!   sender → receiver : SPAKE2 message (framed)
//!   sender → receiver : AEAD chunks (framed), then END marker (len 0)
//!   receiver → sender : receipt JSON (framed): sha256 + fingerprint
//! Both sides derive the same session key from the human-readable words in
//! the share code; a wrong or missing code fails before any payload moves.

pub mod wordlist;

use crate::crypto::{self, StreamOpen, StreamSeal};
use iroh::{
    Endpoint, RelayMap, RelayMode,
    endpoint::{Connection, RecvStream, SendStream, presets},
    protocol::{AcceptError, ProtocolHandler, Router},
};
use rand_core::{OsRng, RngCore};
use std::sync::{Arc, Mutex};
use std::time::Duration;

pub const ALPN: &[u8] = b"tenv/share/1";
/// Hard cap on a single transfer; .env files are tiny, this is paranoia.
pub const MAX_PAYLOAD_BYTES: usize = 8 * 1024 * 1024;
const SPAKE_MSG_MAX: usize = 128;
const FRAME_LEN_BYTES: usize = 4;
const TRANSFER_TIMEOUT: Duration = Duration::from_secs(120);

#[derive(Debug)]
pub enum TransportError {
    BadCode(String),
    Connect(String),
    Protocol(String),
    Timeout,
}

impl std::fmt::Display for TransportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TransportError::BadCode(m) => write!(f, "invalid share code: {m}"),
            TransportError::Connect(m) => write!(f, "connection failed: {m}"),
            TransportError::Protocol(m) => write!(f, "transfer failed: {m}"),
            TransportError::Timeout => write!(f, "timed out waiting for the receiver"),
        }
    }
}

impl std::error::Error for TransportError {}

impl From<crypto::CryptoError> for TransportError {
    fn from(value: crypto::CryptoError) -> Self {
        TransportError::Protocol(value.to_string())
    }
}

pub type Result<T> = std::result::Result<T, TransportError>;

// Re-exports so downstream code (and tests) can build addresses without
// depending on iroh directly.
pub use iroh::{EndpointAddr, EndpointId, TransportAddr};

/// Wrap a raw UDP address as a direct-IP transport candidate.
pub fn ip_transport(addr: std::net::SocketAddr) -> TransportAddr {
    TransportAddr::Ip(addr)
}

// ---------- share codes ----------

/// Four random dictionary words joined by `-` (32 bits of entropy).
pub fn generate_password() -> String {
    let mut buf = [0u8; 4];
    OsRng.fill_bytes(&mut buf);
    buf.iter()
        .map(|b| wordlist::WORDS[*b as usize])
        .collect::<Vec<_>>()
        .join("-")
}

/// `word-word-word-word-<endpoint id hex>`
pub fn encode_code(password: &str, endpoint_id: &EndpointId) -> String {
    format!("{password}-{}", endpoint_id)
}

pub fn decode_code(code: &str) -> Result<(String, EndpointId)> {
    let parts: Vec<&str> = code.trim().split('-').collect();
    if parts.len() != 5 {
        return Err(TransportError::BadCode(format!(
            "expected 5 dash-separated parts, got {}",
            parts.len()
        )));
    }
    let id: EndpointId = parts[4]
        .parse()
        .map_err(|_| TransportError::BadCode("endpoint id is not valid hex".into()))?;
    Ok((parts[..4].join("-"), id))
}

// ---------- wire framing ----------

async fn write_frame(stream: &mut SendStream, bytes: &[u8]) -> Result<()> {
    let len = u32::try_from(bytes.len())
        .map_err(|_| TransportError::Protocol("frame too large".into()))?;
    stream
        .write_all(&len.to_be_bytes())
        .await
        .map_err(|e| TransportError::Protocol(e.to_string()))?;
    stream
        .write_all(bytes)
        .await
        .map_err(|e| TransportError::Protocol(e.to_string()))?;
    Ok(())
}

async fn read_frame(stream: &mut RecvStream, max: usize) -> Result<Vec<u8>> {
    let mut len_buf = [0u8; FRAME_LEN_BYTES];
    stream
        .read_exact(&mut len_buf)
        .await
        .map_err(|e| TransportError::Protocol(format!("length prefix: {e}")))?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > max {
        return Err(TransportError::Protocol(format!(
            "frame of {len} bytes exceeds limit"
        )));
    }
    let mut buf = vec![0u8; len];
    stream
        .read_exact(&mut buf)
        .await
        .map_err(|e| TransportError::Protocol(format!("body: {e}")))?;
    Ok(buf)
}

// ---------- endpoints ----------

fn build_relay_map(url: &str) -> Result<RelayMap> {
    RelayMap::try_from_iter([url]).map_err(|e| TransportError::BadCode(format!("relay url: {e}")))
}

async fn bind_endpoint(custom_relay: Option<&str>) -> Result<Endpoint> {
    match custom_relay {
        None => Endpoint::bind(presets::N0).await,
        Some(url) => {
            let map = build_relay_map(url)?;
            Endpoint::builder(presets::N0)
                .relay_mode(RelayMode::Custom(map))
                .bind()
                .await
        }
    }
    .map_err(|e| TransportError::Connect(e.to_string()))
}

// ---------- sender ----------

#[derive(Debug)]
struct ShareInner {
    password: Vec<u8>,
    payload_sha256: [u8; 32],
    payload: Mutex<Option<Vec<u8>>>,
    done: tokio::sync::mpsc::UnboundedSender<Result<TransferReceipt>>,
}

#[derive(Debug, Clone)]
struct ShareHandler(Arc<ShareInner>);

/// What the sender learns once the receiver acknowledges the transfer.
#[derive(Debug)]
pub struct TransferReceipt {
    pub receiver_fingerprint: String,
}

impl ProtocolHandler for ShareHandler {
    async fn accept(&self, connection: Connection) -> std::result::Result<(), AcceptError> {
        let outcome = self.serve(connection).await;
        let _ = self.0.done.send(outcome);
        Ok(())
    }
}

impl ShareHandler {
    async fn serve(&self, connection: Connection) -> Result<TransferReceipt> {
        let (mut send, mut recv) = connection
            .accept_bi()
            .await
            .map_err(|e| TransportError::Protocol(e.to_string()))?;

        // 1. peer's SPAKE2 message arrives first (receiver initiates).
        let peer_msg = read_frame(&mut recv, SPAKE_MSG_MAX).await?;
        let (session, my_msg) = crypto::spake::begin(&self.0.password)
            .map_err(|_| TransportError::Protocol("handshake init".into()))?;
        write_frame(&mut send, &my_msg).await?;
        let session_key = session
            .finish(&peer_msg)
            .map_err(|_| TransportError::Protocol("handshake failed".into()))?;

        // 2. payload in sealed, counter-nonce chunks, then END marker.
        let payload = self
            .0
            .payload
            .lock()
            .expect("payload lock")
            .take()
            .ok_or_else(|| TransportError::Protocol("already served".into()))?;
        let mut sealer = StreamSeal::new(*session_key);
        for chunk in payload.chunks(64 * 1024) {
            let sealed = sealer.seal_chunk(chunk);
            write_frame(&mut send, &sealed).await?;
        }
        write_frame(&mut send, &[]).await?; // END marker (unsealed empty frame)

        // 3. receipt back from the receiver.
        let receipt_raw = read_frame(&mut recv, 4096).await?;
        let receipt: TransferReceiptWire = serde_json::from_slice(&receipt_raw)
            .map_err(|e| TransportError::Protocol(format!("receipt: {e}")))?;
        if receipt.payload_sha256 != self.0.payload_sha256 {
            return Err(TransportError::Protocol(
                "receiver got corrupted data".into(),
            ));
        }

        // Sender initiates close so the receiver's wait-for-close resolves;
        // the reverse order deadlocks (each waiting on the other).
        connection.close(0u32.into(), b"ok");

        Ok(TransferReceipt {
            receiver_fingerprint: receipt.receiver_fingerprint,
        })
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
struct TransferReceiptWire {
    payload_sha256: [u8; 32],
    receiver_fingerprint: String,
}

/// A live share that is listening and has not been picked up yet.
pub struct LiveShare {
    router: Router,
    code: String,
    done: tokio::sync::mpsc::UnboundedReceiver<Result<TransferReceipt>>,
}

impl LiveShare {
    /// Bind an endpoint, arm the one-shot listener, return the code to show.
    pub async fn start(
        password: &str,
        payload: Vec<u8>,
        custom_relay: Option<&str>,
    ) -> Result<Self> {
        let endpoint = bind_endpoint(custom_relay).await?;
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();

        let inner = Arc::new(ShareInner {
            password: password.as_bytes().to_vec(),
            payload_sha256: crypto::kdf::sha256(&payload),
            payload: Mutex::new(Some(payload)),
            done: tx,
        });
        let handler = ShareHandler(inner);

        let router = Router::builder(endpoint).accept(ALPN, handler).spawn();
        router.endpoint().online().await;

        let id = router.endpoint().id();
        Ok(Self {
            router,
            code: encode_code(password, &id),
            done: rx,
        })
    }

    pub fn code(&self) -> &str {
        &self.code
    }

    /// Locally bound UDP ports; useful for LAN-direct dialing and tests.
    pub fn local_ports(&self) -> Vec<std::net::SocketAddr> {
        self.router.endpoint().bound_sockets()
    }

    /// Wait for the receiver. Errors include timeouts and handshake failures.
    pub async fn wait_done(mut self) -> Result<TransferReceipt> {
        let outcome = tokio::time::timeout(TRANSFER_TIMEOUT, self.done.recv()).await;
        self.router.shutdown().await.ok();
        match outcome {
            Ok(Some(Ok(receipt))) => Ok(receipt),
            Ok(Some(Err(e))) => Err(e),
            _ => Err(TransportError::Timeout),
        }
    }
}

// ---------- receiver ----------

pub struct ReceivedShare {
    pub payload: Vec<u8>,
    pub sender_endpoint_id: EndpointId,
}

/// Dial the sender, complete the SPAKE2 handshake with the words from the
/// code, and pull the encrypted payload across. `my_fingerprint` travels in
/// the receipt so the sender can log who picked the share up.
pub async fn receive_live(
    code: &str,
    custom_relay: Option<&str>,
    my_fingerprint: &str,
) -> Result<ReceivedShare> {
    let (password, endpoint_id) = decode_code(code)?;

    let endpoint = bind_endpoint(custom_relay).await?;
    let conn = endpoint
        .connect(EndpointAddr::from(endpoint_id), ALPN)
        .await
        .map_err(|e| TransportError::Connect(e.to_string()))?;

    let result = receive_over(&conn, &password, my_fingerprint).await;
    conn.close(0u32.into(), b"done");
    endpoint.close().await;
    result
}

/// Like [`receive_live`] but dialing a caller-provided address directly
/// (used by tests and future LAN discovery; no code decoding involved).
pub async fn receive_direct(
    addr: EndpointAddr,
    password: &str,
    custom_relay: Option<&str>,
    my_fingerprint: &str,
) -> Result<ReceivedShare> {
    let endpoint = bind_endpoint(custom_relay).await?;
    let conn = endpoint
        .connect(addr, ALPN)
        .await
        .map_err(|e| TransportError::Connect(e.to_string()))?;
    let result = receive_over(&conn, password, my_fingerprint).await;
    conn.close(0u32.into(), b"done");
    endpoint.close().await;
    result
}

async fn receive_over(
    conn: &Connection,
    password: &str,
    my_fingerprint: &str,
) -> Result<ReceivedShare> {
    let (mut send, mut recv) = conn
        .open_bi()
        .await
        .map_err(|e| TransportError::Protocol(e.to_string()))?;

    // We speak first so the sender can finish against our message.
    let (session, my_msg) = crypto::spake::begin(password.as_bytes())
        .map_err(|_| TransportError::Protocol("handshake init".into()))?;
    write_frame(&mut send, &my_msg).await?;

    let peer_msg = read_frame(&mut recv, SPAKE_MSG_MAX).await?;
    let session_key = session
        .finish(&peer_msg)
        .map_err(|_| TransportError::Protocol("wrong code or tampered handshake".into()))?;

    // Pull sealed chunks until the unsealed END marker (empty frame).
    let mut opener = StreamOpen::new(*session_key);
    let mut payload = Vec::new();
    loop {
        let frame = read_frame(&mut recv, MAX_PAYLOAD_BYTES).await?;
        if frame.is_empty() {
            break;
        }
        let plain = opener.open_chunk(&frame)?;
        if payload.len() + plain.len() > MAX_PAYLOAD_BYTES {
            return Err(TransportError::Protocol(
                "payload exceeds size limit".into(),
            ));
        }
        payload.extend_from_slice(&plain);
    }

    // Acknowledge integrity so the sender can report success confidently.
    let receipt = TransferReceiptWire {
        payload_sha256: crypto::kdf::sha256(&payload),
        receiver_fingerprint: my_fingerprint.to_string(),
    };
    let receipt_raw =
        serde_json::to_vec(&receipt).map_err(|e| TransportError::Protocol(e.to_string()))?;
    write_frame(&mut send, &receipt_raw).await?;
    send.finish()
        .map_err(|e| TransportError::Protocol(e.to_string()))?;

    // Hold the connection until the sender confirms it consumed the receipt;
    // an immediate close here would truncate the in-flight frame.
    conn.closed().await;

    Ok(ReceivedShare {
        payload,
        sender_endpoint_id: conn.remote_id(),
    })
}
