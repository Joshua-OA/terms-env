//! Vault: the encrypted local store. One vault per machine holding all
//! project namespaces, directory links, and the device identity key.
//!
//! On-disk layout (`$TENV_HOME` or platform data dir / `terms-env`):
//!   vault.enc  — magic `TNVV` ‖ ver ‖ kdf_id ‖ [salt16] ‖ nonce24 ‖ ct
//!                kdf_id 0 = key lives in OS keychain
//!                kdf_id 1 = key = Argon2id(passphrase, salt)
//! Unlock keys come from a [`KeyStore`] implementation so tests can inject a
//! file-backed double instead of touching the real OS keychain.

use crate::crypto::{self, DeviceKeys, KdfParams};
use crate::domain::{EnvFile, EnvVar};
use crate::fsutil::atomic_write;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

pub const MAGIC: &[u8; 4] = b"TNVV";
pub const FORMAT_VERSION: u8 = 1;

const KDF_KEYCHAIN: u8 = 0;
const KDF_ARGON2: u8 = 1;
const KEYCHAIN_SERVICE: &str = "terms-env";
const KEYCHAIN_USER: &str = "vault-key";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VaultError {
    NotFound,
    AlreadyExists,
    WrongPassphrase,
    Locked,
    NoLinkForDirectory(String),
    UnknownProject(String),
    Keychain(String),
    Io(String),
    Corrupt(String),
}

impl fmt::Display for VaultError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VaultError::NotFound => write!(f, "no vault found; run `tnv init` first"),
            VaultError::AlreadyExists => write!(f, "vault already exists here"),
            VaultError::WrongPassphrase => write!(f, "wrong passphrase"),
            VaultError::Locked => write!(f, "vault key not found in keychain"),
            VaultError::NoLinkForDirectory(dir) => {
                write!(
                    f,
                    "this directory is not linked to any project ({dir}); run `tnv link`"
                )
            }
            VaultError::UnknownProject(p) => write!(f, "unknown project `{p}`"),
            VaultError::Keychain(e) => write!(f, "keychain error: {e}"),
            VaultError::Io(e) => write!(f, "io error: {e}"),
            VaultError::Corrupt(e) => write!(f, "vault corrupt: {e}"),
        }
    }
}

impl std::error::Error for VaultError {}

impl From<std::io::Error> for VaultError {
    fn from(e: std::io::Error) -> Self {
        VaultError::Io(e.to_string())
    }
}

pub type Result<T> = std::result::Result<T, VaultError>;

/// Abstraction over where the vault wrapping key lives.
pub trait KeyStore {
    fn store(&self) -> Result<()>;
    fn load_key(&self) -> Result<Option<[u8; 32]>>;
}

/// Production: the OS keychain (macOS Keychain / Windows Credential Manager /
/// freedesktop Secret Service).
pub struct OsKeyring;

impl KeyStore for OsKeyring {
    fn store(&self) -> Result<()> {
        let mut raw = [0u8; 32];
        rand_fill(&mut raw);
        let entry = keyring::Entry::new(KEYCHAIN_SERVICE, KEYCHAIN_USER)
            .map_err(|e| VaultError::Keychain(e.to_string()))?;
        entry
            .set_password(&B64.encode(raw))
            .map_err(|e| VaultError::Keychain(e.to_string()))
    }

    fn load_key(&self) -> Result<Option<[u8; 32]>> {
        let entry = keyring::Entry::new(KEYCHAIN_SERVICE, KEYCHAIN_USER)
            .map_err(|e| VaultError::Keychain(e.to_string()))?;
        match entry.get_password() {
            Ok(b64) => {
                let bytes = B64
                    .decode(b64)
                    .map_err(|e| VaultError::Keychain(e.to_string()))?;
                <[u8; 32]>::try_from(bytes)
                    .map(Some)
                    .map_err(|_| VaultError::Keychain("key length".into()))
            }
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(VaultError::Keychain(e.to_string())),
        }
    }
}

/// Test-only file-backed keystore, selected by TENV_TEST_KEYSTORE. Never used
/// unless that env var points at a path.
pub struct FileKeyStore(pub PathBuf);

impl KeyStore for FileKeyStore {
    fn store(&self) -> Result<()> {
        let mut raw = [0u8; 32];
        rand_fill(&mut raw);
        atomic_write(&self.0, &raw).map_err(|e| VaultError::Io(e.to_string()))
    }

    fn load_key(&self) -> Result<Option<[u8; 32]>> {
        match fs::read(&self.0) {
            Ok(bytes) => <[u8; 32]>::try_from(bytes)
                .map(Some)
                .map_err(|_| VaultError::Keychain("test keystore content invalid".into())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(VaultError::Io(e.to_string())),
        }
    }
}

fn rand_fill(buf: &mut [u8]) {
    use rand_core::{OsRng, RngCore};
    OsRng.fill_bytes(buf);
}

#[derive(Serialize, Deserialize, Default)]
struct VaultData {
    version: u32,
    projects: BTreeMap<String, Vec<EnvVar>>,
    links: BTreeMap<String, String>,
    identity_seed_b64: String,
    x25519_secret_b64: String,
    /// Pinned sender fingerprints -> human label (TOFU registry).
    peers: BTreeMap<String, String>,
}

enum StoredUnlock {
    Keychain,
    Passphrase { salt: [u8; crypto::kdf::SALT_LEN] },
}

pub struct Vault {
    path: PathBuf,
    data: VaultData,
    unlock: StoredUnlock,
    passphrase_hint: Option<String>,
}

pub fn home_dir() -> PathBuf {
    if let Some(custom) = std::env::var_os("TENV_HOME") {
        return PathBuf::from(custom);
    }
    dirs::data_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("terms-env")
}

fn vault_file(home: &Path) -> PathBuf {
    home.join("vault.enc")
}

pub fn exists(home: &Path) -> bool {
    vault_file(home).exists()
}

/// Create a brand-new vault. Fails if one already exists at `home`.
/// `passphrase = None` stores the wrapping key in `keys` (OS keychain in
/// production, injected doubles in tests) instead of deriving from a
/// passphrase.
pub fn init(home: &Path, passphrase: Option<&str>, keys: &dyn KeyStore) -> Result<Vault> {
    let path = vault_file(home);
    if path.exists() {
        return Err(VaultError::AlreadyExists);
    }
    fs::create_dir_all(home)?;

    let stored_unlock = match passphrase {
        None => {
            keys.store()?;
            StoredUnlock::Keychain
        }
        Some(_) => StoredUnlock::Passphrase {
            salt: crypto::random_salt(),
        },
    };

    let data = VaultData {
        version: u32::from(FORMAT_VERSION),
        projects: BTreeMap::new(),
        links: BTreeMap::new(),
        identity_seed_b64: B64.encode(DeviceKeys::generate().to_seed()),
        x25519_secret_b64: {
            let mut raw = [0u8; 32];
            rand_fill(&mut raw);
            B64.encode(raw)
        },
        peers: BTreeMap::new(),
    };
    let mut vault = Vault {
        path,
        data,
        unlock: stored_unlock,
        passphrase_hint: passphrase.map(str::to_string),
    };
    vault.save_with(keys)?;
    Ok(vault)
}

/// Decrypt and load an existing vault.
pub fn open(home: &Path, passphrase: Option<&str>, keys: &dyn KeyStore) -> Result<Vault> {
    let path = vault_file(home);
    let raw = fs::read(&path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            VaultError::NotFound
        } else {
            VaultError::Io(e.to_string())
        }
    })?;

    if raw.len() < 6 || &raw[..4] != MAGIC {
        return Err(VaultError::Corrupt("bad magic".into()));
    }
    let mut offset = 6usize;

    let stored_unlock = match raw[5] {
        KDF_KEYCHAIN => StoredUnlock::Keychain,
        KDF_ARGON2 => {
            const SALT: usize = crypto::kdf::SALT_LEN;
            if raw.len() < offset + SALT {
                return Err(VaultError::Corrupt("short salt".into()));
            }
            let salt: [u8; SALT] = raw[offset..offset + SALT]
                .try_into()
                .expect("checked length");
            offset += SALT;
            StoredUnlock::Passphrase { salt }
        }
        other => return Err(VaultError::Corrupt(format!("unknown kdf id {other}"))),
    };

    if raw.len() < offset + crypto::NONCE_LEN {
        return Err(VaultError::Corrupt("short nonce".into()));
    }
    let nonce: [u8; crypto::NONCE_LEN] = raw[offset..offset + crypto::NONCE_LEN]
        .try_into()
        .expect("checked length");
    offset += crypto::NONCE_LEN;

    let key = unlock_key(&stored_unlock, passphrase, keys)?;
    let plaintext =
        crypto::open(&key, &nonce, &raw[offset..]).map_err(|_| VaultError::WrongPassphrase)?;
    let data: VaultData =
        serde_json::from_slice(&plaintext).map_err(|e| VaultError::Corrupt(e.to_string()))?;

    Ok(Vault {
        path,
        data,
        unlock: stored_unlock,
        passphrase_hint: passphrase.map(str::to_string),
    })
}

fn unlock_key(
    stored: &StoredUnlock,
    passphrase: Option<&str>,
    keys: &dyn KeyStore,
) -> Result<[u8; 32]> {
    match stored {
        StoredUnlock::Keychain => keys.load_key()?.ok_or(VaultError::Locked),
        StoredUnlock::Passphrase { salt } => {
            let pass = passphrase.ok_or(VaultError::Locked)?;
            Ok(*crypto::derive_key(
                pass.as_bytes(),
                salt,
                KdfParams::PRODUCTION,
            ))
        }
    }
}

fn persist(
    path: &Path,
    data: &VaultData,
    unlock: &StoredUnlock,
    passphrase: Option<&str>,
    keys: &dyn KeyStore,
) -> Result<()> {
    let key = unlock_key(unlock, passphrase, keys)?;

    let json = serde_json::to_vec(data).map_err(|e| VaultError::Corrupt(e.to_string()))?;
    let nonce = crypto::random_nonce();
    let ciphertext = crypto::seal(&key, &nonce, &json);

    let mut out = Vec::with_capacity(6 + ciphertext.len());
    out.extend_from_slice(MAGIC);
    out.push(FORMAT_VERSION);
    match unlock {
        StoredUnlock::Keychain => out.push(KDF_KEYCHAIN),
        StoredUnlock::Passphrase { salt } => {
            out.push(KDF_ARGON2);
            out.extend_from_slice(salt);
        }
    }
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);

    atomic_write(path, &out).map_err(|e| VaultError::Io(e.to_string()))
}

impl Vault {
    /// Re-encrypt and atomically replace the vault file. A fresh random nonce
    /// is used every time, so identical data never produces identical files.
    pub fn save(&mut self) -> Result<()> {
        let keys = select_keystore();
        self.save_with(keys.as_ref())
    }

    /// Same as [`save`] but with an explicitly supplied keystore (tests).
    pub fn save_with(&mut self, keys: &dyn KeyStore) -> Result<()> {
        persist(
            &self.path,
            &self.data,
            &self.unlock,
            self.passphrase_hint.as_deref(),
            keys,
        )
    }

    pub fn device_keys(&self) -> Result<DeviceKeys> {
        let seed = B64
            .decode(&self.data.identity_seed_b64)
            .map_err(|e| VaultError::Corrupt(e.to_string()))?;
        let seed: [u8; 32] = seed
            .try_into()
            .map_err(|_| VaultError::Corrupt("identity seed length".into()))?;
        Ok(DeviceKeys::from_seed(&seed))
    }

    pub fn project_names(&self) -> Vec<String> {
        self.data.projects.keys().cloned().collect()
    }

    pub fn has_project(&self, name: &str) -> bool {
        self.data.projects.contains_key(name)
    }

    pub fn project(&self, name: &str) -> Result<EnvFile> {
        let vars = self
            .data
            .projects
            .get(name)
            .ok_or_else(|| VaultError::UnknownProject(name.to_string()))?;
        let mut file = EnvFile::new();
        for var in vars {
            file.set(var.key.clone(), var.value.clone());
        }
        Ok(file)
    }

    pub fn put_project(&mut self, name: impl Into<String>, file: &EnvFile) {
        self.data
            .projects
            .insert(name.into(), file.iter().cloned().collect());
    }

    pub fn remove_project(&mut self, name: &str) -> bool {
        self.data.projects.remove(name).is_some()
    }

    /// Static X25519 secret used to open pubkey-mode shares.
    pub fn x25519_secret(&self) -> Result<[u8; 32]> {
        let raw = B64
            .decode(&self.data.x25519_secret_b64)
            .map_err(|e| VaultError::Corrupt(e.to_string()))?;
        raw.try_into()
            .map_err(|_| VaultError::Corrupt("x25519 secret length".into()))
    }

    /// Pin a sender fingerprint under a human label (first-seen trust).
    pub fn pin_peer(&mut self, fingerprint: impl Into<String>, label: impl Into<String>) {
        self.data.peers.insert(fingerprint.into(), label.into());
    }

    pub fn peer_label(&self, fingerprint: &str) -> Option<&String> {
        self.data.peers.get(fingerprint)
    }

    /// Link the canonical form of `dir` to a project namespace, creating the
    /// namespace if needed. Returns the canonical path recorded.
    pub fn link(&mut self, dir: &Path, project: impl Into<String>) -> Result<String> {
        let project = project.into();
        if !self.data.projects.contains_key(&project) {
            self.put_project(project.clone(), &EnvFile::new());
        }
        let canon = canon_key(dir)?;
        self.data.links.insert(canon.clone(), project.clone());
        Ok(canon)
    }

    pub fn unlink(&mut self, dir: &Path) -> Result<bool> {
        Ok(self.data.links.remove(&canon_key(dir)?).is_some())
    }

    pub fn resolve_link(&self, dir: &Path) -> Result<(String, EnvFile)> {
        let canon = canon_key(dir)?;
        let project = self
            .data
            .links
            .get(&canon)
            .ok_or_else(|| VaultError::NoLinkForDirectory(canon.clone()))?
            .clone();
        let file = self.project(&project)?;
        Ok((project, file))
    }
}

fn canonical(dir: &Path) -> Result<PathBuf> {
    dir.canonicalize()
        .map_err(|e| VaultError::Io(e.to_string()))
}

/// CLI-level keystore selection: tests point TENV_TEST_KEYSTORE at a file;
/// production uses the OS keychain. The library itself never reads env vars.
pub fn select_keystore() -> Box<dyn KeyStore> {
    match std::env::var_os("TENV_TEST_KEYSTORE") {
        Some(path) => Box::new(FileKeyStore(PathBuf::from(path))),
        None => Box::new(OsKeyring),
    }
}

/// Links are keyed by canonical path rendered as a string.
fn canon_key(dir: &Path) -> Result<String> {
    Ok(canonical(dir)?.display().to_string())
}
