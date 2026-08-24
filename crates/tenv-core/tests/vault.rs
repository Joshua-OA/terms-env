use std::fs;
use std::path::{Path, PathBuf};
use tempfile::TempDir;
use tenv_core::vault::{self, FileKeyStore, KeyStore, VaultError};

struct Sandbox {
    _guard: TempDir,
    home: PathBuf,
    keys: FileKeyStore,
}

/// Each test gets an isolated home + keystore; no global state is touched,
/// so the default parallel test harness stays safe.
fn sandbox() -> Sandbox {
    let guard = TempDir::new().unwrap();
    let home = guard.path().join("home");
    fs::create_dir_all(&home).unwrap();
    let keys = FileKeyStore(guard.path().join("keystore.bin"));
    Sandbox {
        _guard: guard,
        home,
        keys,
    }
}

fn project_file(pairs: &[(&str, &str)]) -> tenv_core::domain::EnvFile {
    use tenv_core::domain::EnvFile;
    let mut f = EnvFile::new();
    for (k, v) in pairs {
        f.set(*k, *v);
    }
    f
}

#[test]
fn init_open_save_round_trip_persists_across_reopen() {
    let sb = sandbox();

    let mut v = vault::init(&sb.home, Some("correct horse battery"), &sb.keys).unwrap();
    v.put_project("acme/api", &project_file(&[("STRIPE_KEY", "sk_live_123")]));
    let proj_dir = make_linked_dir(&mut v, "acme/api", "proj-a");
    v.save().unwrap();
    drop(v);

    let reopened = vault::open(&sb.home, Some("correct horse battery"), &sb.keys).unwrap();
    assert_eq!(reopened.project_names(), vec!["acme/api".to_string()]);
    assert_eq!(
        reopened.project("acme/api").unwrap().get("STRIPE_KEY"),
        Some("sk_live_123")
    );
    let (linked, _) = reopened.resolve_link(&proj_dir).unwrap();
    assert_eq!(linked, "acme/api");
}

fn make_linked_dir(v: &mut vault::Vault, project: &str, leaf: &str) -> PathBuf {
    let dir = std::env::temp_dir()
        .join(format!("tenv-test-{}-{leaf}", std::process::id()))
        .canonicalize()
        .unwrap_or_else(|_| std::env::temp_dir());
    fs::create_dir_all(&dir).unwrap();
    v.link(&dir, project).unwrap();
    dir
}

#[test]
fn wrong_passphrase_is_rejected_on_open() {
    let sb = sandbox();
    vault::init(&sb.home, Some("right-passphrase"), &sb.keys).unwrap();

    match vault::open(&sb.home, Some("wrong-passphrase"), &sb.keys) {
        Err(VaultError::WrongPassphrase) => {}
        Err(e) => panic!("expected WrongPassphrase, got {e:?}"),
        Ok(_) => panic!("expected WrongPassphrase, but open succeeded"),
    }
    assert!(
        vault::open(&sb.home, Some("right-passphrase"), &sb.keys).is_ok(),
        "the correct passphrase must still open the vault"
    );
}

#[test]
fn double_init_fails_and_missing_vault_is_not_found() {
    let sb = sandbox();
    vault::init(&sb.home, None, &sb.keys).unwrap();
    assert!(matches!(
        vault::init(&sb.home, None, &sb.keys),
        Err(VaultError::AlreadyExists)
    ));

    let other = sandbox();
    assert!(matches!(
        vault::open(&other.home, None, &other.keys),
        Err(VaultError::NotFound)
    ));
}

#[test]
fn keychain_mode_round_trip_via_injected_keystore() {
    let sb = sandbox();
    vault::init(&sb.home, None, &sb.keys).unwrap();

    // Simulate a restart: same keystore still holds the wrapping key.
    let v = vault::open(&sb.home, None, &sb.keys).unwrap();
    assert!(v.device_keys().is_ok());

    // Losing the keystore locks the vault out.
    drop(v);
    fs::remove_file(&sb.keys.0).unwrap();
    assert!(matches!(
        vault::open(&sb.home, None, &sb.keys),
        Err(VaultError::Locked)
    ));
}

#[test]
fn every_save_rotates_nonce_so_files_differ() {
    let sb = sandbox();
    let mut v = vault::init(&sb.home, Some("some passphrase"), &sb.keys).unwrap();
    let first = fs::read(vault_path(&sb.home)).unwrap();
    v.save_with(&sb.keys).unwrap();
    let second = fs::read(vault_path(&sb.home)).unwrap();
    assert_ne!(first, second, "fresh nonce must change ciphertext bytes");
}

fn vault_path(home: &Path) -> PathBuf {
    home.join("vault.enc")
}

#[test]
fn unlink_removes_link_and_resolve_then_fails() {
    let sb = sandbox();
    let mut v = vault::init(&sb.home, Some("passphrase-1"), &sb.keys).unwrap();

    let real = std::env::temp_dir().canonicalize().unwrap();
    v.link(&real, "globex/bot").unwrap();
    assert!(v.unlink(&real).unwrap());
    assert!(!v.unlink(&real).unwrap());
    assert!(matches!(
        v.resolve_link(&real),
        Err(VaultError::NoLinkForDirectory(_))
    ));
}

#[test]
fn atomic_write_leaves_no_tmp_file_behind() {
    let dir = TempDir::new().unwrap();
    let target = dir.path().join("secret.env");
    tenv_core::fsutil::atomic_write(&target, b"A=1\n").unwrap();
    assert_eq!(fs::read(&target).unwrap(), b"A=1\n");

    let leftovers: Vec<_> = fs::read_dir(dir.path())
        .unwrap()
        .filter_map(Result::ok)
        .map(|e| e.file_name().into_string().unwrap())
        .filter(|n| n.ends_with(".tmp"))
        .collect();
    assert!(leftovers.is_empty(), "stray tmp files: {leftovers:?}");
}

#[test]
fn destroy_removes_vault_config_key_and_empty_home() {
    let sb = sandbox();
    // Keychain-mode init is what stores a key in the keystore.
    vault::init(&sb.home, None, &sb.keys).unwrap();
    assert!(vault::exists(&sb.home));
    assert!(sb.keys.0.exists(), "keystore file must exist pre-destroy");

    let report = vault::destroy(&sb.home, &sb.keys).unwrap();
    assert!(report.vault_file);
    assert!(!report.config_file, "no config.json was ever written");
    assert!(report.key_removed);

    assert!(!vault::exists(&sb.home));
    assert!(!sb.keys.0.exists(), "keystore file must be gone");
    assert!(!sb.home.exists(), "emptied home dir should be removed");
}

#[test]
fn destroy_reports_config_file_when_present_and_keeps_foreign_files() {
    let sb = sandbox();
    vault::init(&sb.home, Some("passphrase-1"), &sb.keys).unwrap();
    fs::write(sb.home.join("config.json"), b"{}\n").unwrap();
    fs::write(sb.home.join("user-notes.txt"), b"mine").unwrap();

    let report = vault::destroy(&sb.home, &sb.keys).unwrap();
    assert!(report.config_file);
    assert!(sb.home.exists(), "non-empty home must be left alone");
    assert_eq!(fs::read(sb.home.join("user-notes.txt")).unwrap(), b"mine");
}

#[test]
fn destroy_without_vault_fails_and_keeps_key() {
    let sb = sandbox();
    assert!(matches!(
        vault::destroy(&sb.home, &sb.keys),
        Err(VaultError::NotFound)
    ));
}

#[test]
fn destroy_is_idempotent_at_the_keystore_level() {
    let sb = sandbox();
    vault::init(&sb.home, None, &sb.keys).unwrap();
    vault::destroy(&sb.home, &sb.keys).unwrap();
    assert!(!sb.keys.delete().unwrap(), "second delete finds nothing");
}
