use assert_cmd::Command;
use std::fs;
use std::path::PathBuf;
use tempfile::TempDir;

struct Env {
    _guard: TempDir,
    home: TempDir,
}

impl Env {
    fn new() -> Self {
        Self {
            _guard: TempDir::new().unwrap(),
            home: TempDir::new().unwrap(),
        }
    }

    fn cmd(&self) -> Command {
        let mut cmd = Command::cargo_bin("tnv").unwrap();
        cmd.env("TENV_HOME", self.home.path());
        // Tests never touch the real OS keychain.
        let keystore = self._guard.path().join("keystore.bin");
        fs::write(&keystore, [7u8; 32]).unwrap();
        cmd.env("TENV_TEST_KEYSTORE", &keystore);
        cmd
    }
}

fn write_passphrase_file(dir: &TempDir, name: &str, passphrase: &str) -> PathBuf {
    let path = dir.path().join(format!("{name}.txt"));
    fs::write(&path, format!("{passphrase}\n")).unwrap();
    path
}

#[test]
fn version_flag_works() {
    Env::new()
        .cmd()
        .arg("--version")
        .assert()
        .success()
        .stdout(predicates::str::starts_with("tnv 0.1."));
}

#[test]
fn init_add_list_get_flow_with_passphrase_vault() {
    let env = Env::new();
    let pass = write_passphrase_file(&env._guard, "pass", "hunter2hunter2");

    let project = env._guard.path().join("myproj");
    fs::create_dir_all(&project).unwrap();

    env.cmd()
        .args([
            "--passphrase-file",
            pass.to_str().unwrap(),
            "init",
            "--passphrase",
        ])
        .assert()
        .success();

    // Link this directory as acme/api.
    env.cmd()
        .args([
            "--passphrase-file",
            pass.to_str().unwrap(),
            "link",
            "acme/api",
        ])
        .current_dir(&project)
        .assert()
        .success();

    env.cmd()
        .args([
            "--passphrase-file",
            pass.to_str().unwrap(),
            "add",
            "STRIPE_KEY=sk_live_999",
        ])
        .current_dir(&project)
        .assert()
        .success();

    env.cmd()
        .args(["--passphrase-file", pass.to_str().unwrap(), "list"])
        .assert()
        .success()
        .stdout(predicates::str::contains("acme/api"));

    env.cmd()
        .args([
            "--passphrase-file",
            pass.to_str().unwrap(),
            "get",
            "STRIPE_KEY",
        ])
        .current_dir(&project)
        .assert()
        .success()
        .stdout("sk_live_999\n");
}

#[test]
fn wrong_passphrase_via_file_fails_cleanly() {
    let env = Env::new();
    let right = write_passphrase_file(&env._guard, "right", "right-pass-123");
    let wrong = write_passphrase_file(&env._guard, "wrong", "wrong-pass-456");

    env.cmd()
        .args([
            "--passphrase-file",
            right.to_str().unwrap(),
            "init",
            "--passphrase",
        ])
        .assert()
        .success();

    env.cmd()
        .args(["--passphrase-file", wrong.to_str().unwrap(), "list"])
        .assert()
        .failure()
        .stderr(predicates::str::contains("wrong passphrase"));
}

#[test]
fn rm_removes_key_and_missing_key_errors() {
    let env = Env::new();
    let pass = write_passphrase_file(&env._guard, "pass", "long-enough-pass");
    let project = env._guard.path().join("p2");
    fs::create_dir_all(&project).unwrap();
    let pf = pass.to_str().unwrap().to_string();

    env.cmd()
        .args(["--passphrase-file", &pf, "init", "--passphrase"])
        .assert()
        .success();
    env.cmd()
        .args(["--passphrase-file", &pf, "link", "x/y"])
        .current_dir(&project)
        .assert()
        .success();
    env.cmd()
        .args(["--passphrase-file", &pf, "add", "A=1"])
        .current_dir(&project)
        .assert()
        .success();

    env.cmd()
        .args(["--passphrase-file", &pf, "rm", "A"])
        .current_dir(&project)
        .assert()
        .success();
    env.cmd()
        .args(["--passphrase-file", &pf, "get", "A"])
        .current_dir(&project)
        .assert()
        .failure();
}

#[test]
fn sync_applies_disk_edits_into_vault_with_yes() {
    let env = Env::new();
    let pass = write_passphrase_file(&env._guard, "pass", "long-enough-pass");
    let project = env._guard.path().join("syncproj");
    fs::create_dir_all(&project).unwrap();
    let pf = pass.to_str().unwrap().to_string();
    let base = ["--passphrase-file", &pf];

    env.cmd()
        .args(base)
        .arg("init")
        .arg("--passphrase")
        .assert()
        .success();
    env.cmd()
        .args(base)
        .arg("link")
        .arg("s/p")
        .current_dir(&project)
        .assert()
        .success();
    env.cmd()
        .args(base)
        .arg("add")
        .arg("OLD=1")
        .arg("--yes")
        .current_dir(&project)
        .assert()
        .success();

    fs::write(
        project.join(".env"),
        "OLD=1\nNEW=hello world\nOLD=1\nEXTRA=x y\n",
    )
    .unwrap();

    env.cmd()
        .args(base)
        .arg("sync")
        .arg("--yes")
        .current_dir(&project)
        .assert()
        .success();

    env.cmd()
        .args(base)
        .arg("get")
        .arg("NEW")
        .arg("--yes")
        .current_dir(&project)
        .assert()
        .success()
        .stdout("hello world\n");
}

#[test]
fn sync_without_link_fails_with_hint() {
    let env = Env::new();
    let pass = write_passphrase_file(&env._guard, "pass", "long-enough-pass");
    let bare = env._guard.path().join("unlinked");
    fs::create_dir_all(&bare).unwrap();

    env.cmd()
        .args([
            "--passphrase-file",
            pass.to_str().unwrap(),
            "init",
            "--passphrase",
        ])
        .assert()
        .success();

    env.cmd()
        .args(["--passphrase-file", pass.to_str().unwrap(), "sync"])
        .current_dir(&bare)
        .assert()
        .failure()
        .stderr(predicates::str::contains("not linked"));
}

#[test]
fn uninstall_yes_removes_vault_then_reports_missing() {
    let env = Env::new();
    let pass = write_passphrase_file(&env._guard, "pass", "hunter2hunter2");

    env.cmd()
        .args([
            "--passphrase-file",
            pass.to_str().unwrap(),
            "init",
            "--passphrase",
        ])
        .assert()
        .success();

    env.cmd()
        .args(["--yes", "uninstall"])
        .assert()
        .success()
        .stdout(predicates::str::contains("removed vault file"));

    // The vault is gone; a second uninstall must fail, and list must too.
    env.cmd().arg("uninstall").assert().failure();
    env.cmd()
        .args(["--passphrase-file", pass.to_str().unwrap(), "list"])
        .assert()
        .failure();
}

#[test]
fn uninstall_without_yes_denied_in_non_interactive_session() {
    let env = Env::new();
    let pass = write_passphrase_file(&env._guard, "pass", "hunter2hunter2");

    env.cmd()
        .args([
            "--passphrase-file",
            pass.to_str().unwrap(),
            "init",
            "--passphrase",
        ])
        .assert()
        .success();

    // Tests run without a TTY; default-deny must protect the vault.
    env.cmd()
        .arg("uninstall")
        .assert()
        .failure()
        .stderr(predicates::str::contains("--yes"));

    env.cmd()
        .args(["--passphrase-file", pass.to_str().unwrap(), "list"])
        .assert()
        .success();
}
