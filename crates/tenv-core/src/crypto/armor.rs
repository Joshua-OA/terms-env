//! Armor codec: `TENV1 <mode>` header line followed by base64 lines.

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;

use super::CryptoError;

const HEADER_PREFIX: &str = "TENV1 ";
const LINE_WIDTH: usize = 76;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Passphrase,
    Pubkey,
}

impl Mode {
    pub fn label(self) -> &'static str {
        match self {
            Mode::Passphrase => "passphrase",
            Mode::Pubkey => "pubkey",
        }
    }

    fn from_label(label: &str) -> Option<Self> {
        match label {
            "passphrase" => Some(Mode::Passphrase),
            "pubkey" => Some(Mode::Pubkey),
            _ => None,
        }
    }
}

pub fn armor(mode: Mode, body: &[u8]) -> String {
    let encoded = B64.encode(body);
    let mut out = format!("{}{}\n", HEADER_PREFIX, mode.label());
    for chunk in encoded.as_bytes().chunks(LINE_WIDTH) {
        out.push_str(std::str::from_utf8(chunk).expect("base64 is ascii"));
        out.push('\n');
    }
    out
}

pub fn dearmor(text: &str) -> Result<(Mode, Vec<u8>), CryptoError> {
    let mut lines = text.lines().map(str::trim).filter(|l| !l.is_empty());

    let header = lines
        .next()
        .and_then(|l| l.strip_prefix(HEADER_PREFIX))
        .ok_or_else(|| CryptoError::MalformedArmor("missing TENV1 header".into()))?;
    let mode = Mode::from_label(header)
        .ok_or_else(|| CryptoError::MalformedArmor("unknown mode".into()))?;

    let mut joined = String::new();
    for line in lines {
        if !line
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'='))
        {
            return Err(CryptoError::MalformedArmor(format!("bad line `{line}`")));
        }
        joined.push_str(line);
    }
    if joined.is_empty() {
        return Err(CryptoError::MalformedArmor("no payload".into()));
    }
    let body = B64
        .decode(joined.as_bytes())
        .map_err(|e| CryptoError::MalformedArmor(format!("base64: {e}")))?;
    Ok((mode, body))
}
