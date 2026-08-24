use clap::{Parser, Subcommand};
use std::io::{BufRead, IsTerminal, Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use tenv_cli::ui;
use tenv_core::crypto::{DeviceKeys, fingerprint};
use tenv_core::domain::EnvFile;
use tenv_core::envparser::{self, Change};
use tenv_core::share::{self, SignedPayload};
use tenv_core::vault::{self, Vault};

const RECEIVE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(90);
const RELAY_COMPOSE: &str = r#"# terms-env team relay — stock iroh-relay, blind to all traffic.
# Start:  docker compose up -d     Stop: docker compose down
# Point teammates here:  tnv config relay wss://<this-host>
services:
  tenv-relay:
    image: ${IROH_RELAY_IMAGE:-ghcr.io/n0-computer/iroh-relay:v1.0.3}
    command: ["--dev", "serve"]
    ports:
      - "443:443"
      - "80:80"
    restart: unless-stopped
"#;

#[derive(Parser)]
#[command(
    name = "tnv",
    version,
    about = "Store and share .env secrets securely, terminal to terminal"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,

    /// Read the vault passphrase from this file instead of prompting.
    #[arg(long, global = true, value_name = "FILE")]
    passphrase_file: Option<PathBuf>,

    /// Assume yes; apply all proposed changes without asking.
    #[arg(long, global = true)]
    yes: bool,
}

#[derive(Subcommand)]
enum Cmd {
    /// Create a new vault. Default unlock: OS keychain.
    Init {
        /// Use a master passphrase instead of the OS keychain.
        #[arg(long)]
        passphrase: bool,
    },
    /// Link the current directory to a project namespace.
    /// Without a name, offers the current folder's name.
    Link { name: Option<String> },
    /// Apply .env file changes from the current directory into its project.
    Sync,
    /// Add or update KEY=VALUE in the linked project.
    Add { pair: String },
    /// Remove a key from the linked project.
    Rm { key: String },
    /// Print one key's value.
    Get { key: String },
    /// List projects and where the current directory points.
    List,
    /// Share a project via a one-time code (or an offline armored blob).
    Share {
        /// Project name; defaults to the directory's link.
        project: Option<String>,
        /// Skip live transfer entirely and print an encrypted blob.
        #[arg(long)]
        offline: bool,
        /// Passphrase-mode blob instead of a code requires this on offline.
        #[arg(long)]
        ttl_secs: Option<u64>,
        /// Relay override for this share.
        #[arg(long)]
        relay: Option<String>,
    },
    /// Receive a share by code into the linked directory.
    Receive {
        code: String,
        #[arg(long)]
        relay: Option<String>,
    },
    /// Import an armored blob from a file (or stdin with "-").
    Import { path: String },
    /// Scaffold a Docker Compose file running your own blind relay.
    RelaySetup,
    /// Point this machine at a team relay ("default" restores n0 public).
    ConfigSet { relay: String },
    /// Permanently remove the vault, relay config, and stored key.
    Uninstall,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match tokio_runtime().block_on(run(&cli)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("error: {err}");
            ExitCode::FAILURE
        }
    }
}

fn tokio_runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime")
}

async fn run(cli: &Cli) -> Result<(), Box<dyn std::error::Error>> {
    match &cli.cmd {
        Cmd::Init { passphrase } => cmd_init(*passphrase, cli),
        Cmd::Link { name } => cmd_link(name.as_deref(), cli),
        Cmd::Sync => cmd_sync(cli),
        Cmd::Add { pair } => cmd_add(pair, cli),
        Cmd::Rm { key } => cmd_rm(key, cli),
        Cmd::Get { key } => cmd_get(key, cli),
        Cmd::List => cmd_list(cli),
        Cmd::Share {
            project,
            offline,
            ttl_secs,
            relay,
        } => {
            cmd_share(
                project.as_deref(),
                *offline,
                *ttl_secs,
                relay.as_deref(),
                cli,
            )
            .await
        }
        Cmd::Receive { code, relay } => cmd_receive(code, relay.as_deref(), cli).await,
        Cmd::Import { path } => cmd_import(path, cli).await,
        Cmd::RelaySetup => cmd_relay_setup(),
        Cmd::ConfigSet { relay } => cmd_config_set(relay),
        Cmd::Uninstall => cmd_uninstall(cli),
    }
}

// ---------- vault plumbing ----------

fn open_vault(cli: &Cli) -> Result<Vault, Box<dyn std::error::Error>> {
    let home = vault::home_dir();
    let keys = vault::select_keystore();
    let supplied = match &cli.passphrase_file {
        Some(path) => Some(std::fs::read_to_string(path)?.trim().to_string()),
        None => None,
    };
    match vault::open(&home, supplied.as_deref(), keys.as_ref()) {
        Ok(v) => Ok(v),
        Err(vault::VaultError::WrongPassphrase | vault::VaultError::Locked)
            if supplied.is_none() =>
        {
            let pass = prompt_existing_passphrase()?;
            Ok(vault::open(&home, Some(&pass), keys.as_ref())?)
        }
        Err(e) => Err(e.into()),
    }
}

fn read_new_passphrase(cli: &Cli) -> Result<String, Box<dyn std::error::Error>> {
    if let Some(path) = &cli.passphrase_file {
        let value = std::fs::read_to_string(path)?.trim().to_string();
        return validate(value);
    }
    if !std::io::stdin().is_terminal() {
        let mut line = String::new();
        std::io::stdin().lock().read_line(&mut line)?;
        return validate(line.trim().to_string());
    }
    let first = rpassword::prompt_password("Choose passphrase: ")?;
    let second = rpassword::prompt_password("Confirm passphrase: ")?;
    if first != second {
        return Err("passphrases do not match".into());
    }
    validate(first)
}

fn prompt_existing_passphrase() -> Result<String, Box<dyn std::error::Error>> {
    if !std::io::stdin().is_terminal() {
        let mut line = String::new();
        std::io::stdin().lock().read_line(&mut line)?;
        return Ok(line.trim().to_string());
    }
    Ok(rpassword::prompt_password("Passphrase: ")?)
}

fn validate(passphrase: String) -> Result<String, Box<dyn std::error::Error>> {
    if passphrase.len() < 8 {
        Err("passphrase must be at least 8 characters".into())
    } else {
        Ok(passphrase)
    }
}

// ---------- basic commands ----------

fn cmd_init(use_passphrase: bool, cli: &Cli) -> Result<(), Box<dyn std::error::Error>> {
    let home = vault::home_dir();
    if vault::exists(&home) {
        return Err("vault already exists".into());
    }
    let secret = if use_passphrase {
        Some(read_new_passphrase(cli)?)
    } else {
        None
    };
    let keys = vault::select_keystore();
    vault::init(&home, secret.as_deref(), keys.as_ref())?;
    println!("vault created at {}", home.display());
    println!(
        "unlock via {}.",
        if secret.is_some() {
            "master passphrase"
        } else {
            "OS keychain"
        }
    );
    Ok(())
}

fn cmd_link(name: Option<&str>, cli: &Cli) -> Result<(), Box<dyn std::error::Error>> {
    let mut v = open_vault(cli)?;
    let cwd = std::env::current_dir()?;

    let name = match name {
        Some(explicit) => explicit.to_string(),
        None => {
            let folder = folder_name(&cwd)?;
            if cli.yes {
                println!("linking as `{folder}` (--yes)");
                folder
            } else if ui::is_interactive() {
                print!("use folder name '{folder}' as the project name? [Y/n] ");
                std::io::stdout().flush()?;
                let mut line = String::new();
                std::io::stdin().lock().read_line(&mut line)?;
                match line.trim().to_lowercase().as_str() {
                    "" | "y" | "yes" => folder,
                    "n" | "no" => {
                        print!("project name: ");
                        std::io::stdout().flush()?;
                        let mut custom = String::new();
                        std::io::stdin().lock().read_line(&mut custom)?;
                        let custom = custom.trim().to_string();
                        if custom.is_empty() {
                            return Err("no project name given; aborted".into());
                        }
                        custom
                    }
                    other => return Err(format!("unrecognized answer '{other}'; aborted").into()),
                }
            } else {
                return Err("a project name is required: tnv link <name>
(in a terminal, plain `tnv link` offers the folder name)"
                    .into());
            }
        }
    };

    let canon = v.link(&cwd, &name)?;
    v.save()?;
    println!("{canon} → {name}");
    Ok(())
}

fn folder_name(cwd: &Path) -> Result<String, Box<dyn std::error::Error>> {
    cwd.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .filter(|n| !n.is_empty())
        .ok_or_else(|| {
            "cannot derive a project name from this directory; pass one explicitly".into()
        })
}

fn cmd_sync(cli: &Cli) -> Result<(), Box<dyn std::error::Error>> {
    let mut v = open_vault(cli)?;
    let cwd = std::env::current_dir()?;
    let (project, stored) = v.resolve_link(&cwd)?;

    let disk_path = cwd.join(".env");
    let disk = read_disk_env(&disk_path)?;
    let changes = envparser::diff(&stored, &disk);

    if changes.is_empty() {
        println!("{project}: in sync");
        return Ok(());
    }

    let chosen = choose_changes(
        cli,
        &format!("{project} ← {} ({})", disk_path.display(), changes.len()),
        changes,
    )?;
    let selected = chosen.ok_or("aborted; nothing applied")?;
    if selected.is_empty() && !cli.yes {
        println!("no changes selected");
        return Ok(());
    }

    let mut applied = stored.clone();
    for change in selected {
        apply(&mut applied, change);
    }
    v.put_project(project, &applied);
    v.save()?;
    println!("done");
    Ok(())
}

fn cmd_add(pair: &str, cli: &Cli) -> Result<(), Box<dyn std::error::Error>> {
    let (key, value) = pair.split_once('=').ok_or("expected KEY=VALUE")?;
    let mut v = open_vault(cli)?;
    let cwd = std::env::current_dir()?;
    let (project, mut file) = v.resolve_link(&cwd)?;
    file.set(key.trim().to_string(), value.to_string());
    v.put_project(project, &file);
    v.save()?;
    println!("set {key}");
    Ok(())
}

fn cmd_rm(key: &str, cli: &Cli) -> Result<(), Box<dyn std::error::Error>> {
    let mut v = open_vault(cli)?;
    let cwd = std::env::current_dir()?;
    let (project, mut file) = v.resolve_link(&cwd)?;
    if !file.remove(key) {
        return Err(format!("{key} not found").into());
    }
    v.put_project(project, &file);
    v.save()?;
    println!("removed {key}");
    Ok(())
}

fn cmd_get(key: &str, cli: &Cli) -> Result<(), Box<dyn std::error::Error>> {
    let v = open_vault(cli)?;
    let cwd = std::env::current_dir()?;
    let (_, file) = v.resolve_link(&cwd)?;
    match file.get(key) {
        Some(value) => println!("{value}"),
        None => return Err(format!("{key} not found").into()),
    }
    Ok(())
}

fn cmd_list(cli: &Cli) -> Result<(), Box<dyn std::error::Error>> {
    let v = open_vault(cli)?;
    let cwd = std::env::current_dir()?;
    let here = v.resolve_link(&cwd).map(|(p, _)| p).ok();

    let names = v.project_names();
    for name in &names {
        let count = v.project(name)?.len();
        let marker = if here.as_deref() == Some(name.as_str()) {
            "  ← linked"
        } else {
            ""
        };
        println!("{name} ({count} keys){marker}");
    }
    if names.is_empty() {
        println!("vault is empty");
    }
    Ok(())
}

// ---------- sharing ----------

async fn cmd_share(
    project: Option<&str>,
    offline: bool,
    ttl_secs: Option<u64>,
    relay: Option<&str>,
    cli: &Cli,
) -> Result<(), Box<dyn std::error::Error>> {
    let v = open_vault(cli)?;
    let keys = v.device_keys()?;
    let cwd = std::env::current_dir()?;

    let (project_name, file) = match project {
        Some(name) => (name.to_string(), v.project(name)?),
        None => match v.resolve_link(&cwd) {
            Ok(found) => found,
            Err(vault::VaultError::NoLinkForDirectory(_)) if ui::is_interactive() => {
                // No link here: offer the full vault via the picker screen.
                let here = v.resolve_link(&cwd).map(|(p, _)| p).ok();
                let entries: Vec<ui::picker::ProjectEntry> = v
                    .project_names()
                    .into_iter()
                    .map(|name| {
                        let count = v.project(&name).map(|f| f.len()).unwrap_or(0);
                        ui::picker::ProjectEntry {
                            linked_here: here.as_deref() == Some(name.as_str()),
                            name,
                            key_count: count,
                        }
                    })
                    .collect();
                let chosen =
                    ui::picker::run_picker(entries)?.ok_or("aborted; no project chosen")?;
                (chosen.clone(), v.project(&chosen)?)
            }
            Err(e) => return Err(e.into()),
        },
    };
    let relay_cfg = relay.map(str::to_string).or_else(load_relay_config);
    let relay_opt = relay_cfg.as_deref();

    if offline {
        let pass = ask_share_passphrase()?;
        let blob = share::build_passphrase(&project_name, &file, &keys, ttl_secs, &pass)?;
        println!("{blob}");
        return Ok(());
    }

    let password = tenv_core::transport::generate_password();
    let payload =
        share::payload_bytes(&share::build_payload(&project_name, &file, &keys, ttl_secs));
    let live = tenv_core::transport::LiveShare::start(&password, payload, relay_opt).await?;

    println!("sharing `{project_name}`");
    println!("code: {}", live.code());
    println!("waiting for the receiver… (Ctrl+C aborts)");

    match live.wait_done().await {
        Ok(receipt) => {
            println!("delivered — confirmed by {}", receipt.receiver_fingerprint);
        }
        Err(e) => {
            eprintln!("live transfer failed: {e}");
            if std::io::stdin().is_terminal() {
                eprintln!("falling back to an offline blob:");
                let pass = ask_share_passphrase()?;
                let blob = share::build_passphrase(&project_name, &file, &keys, ttl_secs, &pass)?;
                println!("{blob}");
            } else {
                return Err("live transfer failed; retry with --offline".into());
            }
        }
    }
    Ok(())
}

fn ask_share_passphrase() -> Result<String, Box<dyn std::error::Error>> {
    if !std::io::stdin().is_terminal() {
        return Err("a passphrase is required in non-interactive mode; pipe one in or use --passphrase-file".into());
    }
    Ok(rpassword::prompt_password("Share passphrase: ")?)
}

async fn cmd_receive(
    code: &str,
    relay: Option<&str>,
    cli: &Cli,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut v = open_vault(cli)?;
    let my_keys: DeviceKeys = v.device_keys()?;
    let my_fp = fingerprint(&my_keys.verifying_key());

    println!("connecting…");
    let received = tokio::time::timeout(
        RECEIVE_TIMEOUT,
        tenv_core::transport::receive_live(code, relay.or(load_relay_config().as_deref()), &my_fp),
    )
    .await
    .map_err(|_| "timed out")??;

    let payload: SignedPayload = share::verify_payload(&received.payload)?;
    land_share(&mut v, payload, &my_keys, cli).await
}

async fn cmd_import(path: &str, cli: &Cli) -> Result<(), Box<dyn std::error::Error>> {
    let text = if path == "-" {
        let mut buf = String::new();
        std::io::stdin().lock().read_to_string(&mut buf)?;
        buf
    } else {
        std::fs::read_to_string(path)?
    };

    let mut v = open_vault(cli)?;

    // Pubkey-mode blobs open with our static key at zero KDF cost; only fall
    // back to the passphrase path when that fails decrypt-wise.
    let pubkey_attempt = {
        let sk = v.x25519_secret()?;
        share::open_blob(&text, None, Some(&sk))
    };
    let payload = match pubkey_attempt {
        Ok(p) => p,
        Err(share::ShareError::WrongPassphrase) => {
            let pass = prompt_existing_passphrase()?;
            share::open_blob(&text, Some(&pass), None)?
        }
        Err(e) => return Err(e.into()),
    };
    let keys = v.device_keys()?;
    land_share(&mut v, payload, &keys, cli).await
}

/// Common landing zone: verify trust, merge into vault + write .env.
async fn land_share(
    v: &mut Vault,
    payload: SignedPayload,
    _keys: &DeviceKeys,
    cli: &Cli,
) -> Result<(), Box<dyn std::error::Error>> {
    let vk = ed25519_dalek::VerifyingKey::from_bytes(&payload.sender_pub)?;
    let sender_fp = fingerprint(&vk);

    if let Some(label) = v.peer_label(&sender_fp).cloned() {
        println!("from {label} [{sender_fp}]");
    } else if ui::is_interactive() && !cli.yes {
        use ui::trust::{TrustDecision, run_trust};
        println!("first share from [{sender_fp}]");
        match run_trust(&sender_fp, None)? {
            TrustDecision::AlwaysPin => {
                v.pin_peer(sender_fp.clone(), format!("peer-{sender_fp}"));
                println!("pinned — future shares verify automatically");
            }
            TrustDecision::Once => println!("accepted for this share only"),
            TrustDecision::Reject => return Err("rejected; nothing was written".into()),
        }
    } else if cli.yes {
        println!("unpinned sender accepted via --yes [{sender_fp}]");
    } else {
        return Err(format!(
            "unknown sender {sender_fp}; run interactively to decide, or pass --yes"
        )
        .into());
    }

    let incoming: EnvFile = {
        let mut f = EnvFile::new();
        for var in &payload.vars {
            f.set(var.key.clone(), var.value.clone());
        }
        f
    };

    let cwd = std::env::current_dir()?;
    // Adopt the directory if it has no link yet, so `receive` works in a
    // fresh checkout without a prior `link` step.
    let (mut project, stored) = match v.resolve_link(&cwd) {
        Ok(found) => found,
        Err(vault::VaultError::NoLinkForDirectory(_)) => (payload.project.clone(), EnvFile::new()),
        Err(e) => return Err(e.into()),
    };
    if !v.has_project(&payload.project) {
        project = payload.project.clone();
    }

    let disk_path = cwd.join(".env");
    let disk = read_disk_env(&disk_path)?;

    let full_disk = envparser::merge(&disk, &incoming);
    let changes = envparser::diff(&disk, &full_disk);

    println!(
        "`{}` → {} (expires {})",
        payload.project,
        project,
        payload
            .expires_at
            .map(|t| t.to_string())
            .unwrap_or_else(|| "never".into())
    );

    // Review what will change on disk; vault copy mirrors the same decision.
    let chosen = choose_changes(cli, "incoming changes", changes)?;
    let selected = chosen.ok_or("aborted; nothing written")?;
    if selected.is_empty() && !cli.yes && !ui::is_interactive() {
        println!("no changes selected");
        return Ok(());
    }

    let mut applied_disk = disk.clone();
    let mut applied_vault = stored;
    for change in &selected {
        apply(&mut applied_disk, change.clone());
        apply(&mut applied_vault, change.clone());
    }
    let merged_disk = applied_disk;
    let merged_vault = applied_vault;

    tenv_core::fsutil::atomic_write(&disk_path, envparser::serialize(&merged_disk).as_bytes())
        .map_err(|e| format!("write .env: {e}"))?;
    if v.resolve_link(&cwd).is_err() {
        v.link(&cwd, project.clone())?;
    } else {
        v.put_project(project, &merged_vault);
    }
    v.save()?;
    println!(
        "done — .env written ({} vars, perms 600) and vault updated",
        merged_disk.len()
    );
    Ok(())
}

// ---------- relay + config ----------

fn cmd_relay_setup() -> Result<(), Box<dyn std::error::Error>> {
    let dir = PathBuf::from("tenv-relay");
    std::fs::create_dir_all(&dir)?;
    let compose = dir.join("docker-compose.yml");
    std::fs::write(&compose, RELAY_COMPOSE)?;
    println!("wrote {}", compose.display());
    println!("next steps:");
    println!("  cd tenv-relay && docker compose up -d");
    println!("  tnv config relay wss://<your-host>");
    Ok(())
}

fn cmd_config_set(relay: &str) -> Result<(), Box<dyn std::error::Error>> {
    let cfg = RelayConfig {
        relay_url: (relay != "default").then(|| relay.to_string()),
    };
    let json = serde_json::to_vec_pretty(&cfg)?;
    tenv_core::fsutil::atomic_write(&config_path(), &json)?;
    match cfg.relay_url {
        Some(url) => println!("relay set to {url}"),
        None => println!("relay reset to default (n0 public)"),
    }
    Ok(())
}

fn cmd_uninstall(cli: &Cli) -> Result<(), Box<dyn std::error::Error>> {
    let home = vault::home_dir();
    if !vault::exists(&home) {
        return Err(format!("no vault found at {}", home.display()).into());
    }

    println!("uninstall will PERMANENTLY remove:");
    println!("  - the vault at {}", home.display());
    println!("  - the vault wrapping key in your OS keychain");
    println!("  - the relay config, if any");
    println!(".env files in your projects on disk are NOT touched.");
    println!("This cannot be undone; a new `tnv init` starts from zero.");

    if !cli.yes {
        if !ui::is_interactive() {
            return Err("refusing to uninstall without --yes in a non-interactive session".into());
        }
        print!("type DELETE to confirm: ");
        std::io::stdout().flush()?;
        let mut line = String::new();
        std::io::stdin().lock().read_line(&mut line)?;
        if line.trim() != "DELETE" {
            return Err("aborted; vault untouched".into());
        }
    }

    let keys = vault::select_keystore();
    let report = vault::destroy(&home, keys.as_ref())?;

    println!("removed vault file");
    if report.config_file {
        println!("removed relay config");
    }
    if report.key_removed {
        println!("removed key from OS keychain");
    }
    print!("the tnv binary itself is still installed; remove it with ");
    if cfg!(windows) {
        println!("Remove-Item \"$env:LOCALAPPDATA\\Programs\\terms-env\\tnv.exe\"");
    } else {
        println!("`rm ~/.local/bin/tnv` (or your --prefix bin dir).");
    }
    Ok(())
}

#[derive(serde::Serialize, serde::Deserialize, Default)]
struct RelayConfig {
    relay_url: Option<String>,
}

fn config_path() -> PathBuf {
    vault::home_dir().join("config.json")
}

fn load_relay_config() -> Option<String> {
    let bytes = std::fs::read(config_path()).ok()?;
    serde_json::from_slice::<RelayConfig>(&bytes)
        .ok()?
        .relay_url
}

// ---------- shared UI helpers ----------

/// Decide which changes to apply: TTY users get the ratatui review screen,
/// `--yes` takes everything, pipes get a default-deny listing.
fn choose_changes(
    cli: &Cli,
    title: &str,
    changes: Vec<Change>,
) -> Result<Option<Vec<Change>>, Box<dyn std::error::Error>> {
    if changes.is_empty() {
        return Ok(Some(Vec::new()));
    }
    if cli.yes {
        for c in &changes {
            describe(c);
        }
        return Ok(Some(changes));
    }
    if ui::is_interactive() {
        return Ok(ui::review::run_review(title, changes)?);
    }
    for c in &changes {
        describe(c);
    }
    println!("(non-interactive session; rerun with --yes to apply)");
    Ok(None)
}

fn read_disk_env(path: &PathBuf) -> Result<EnvFile, Box<dyn std::error::Error>> {
    match std::fs::read_to_string(path) {
        Ok(text) => Ok(envparser::parse(&text)?),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(EnvFile::new()),
        Err(e) => Err(e.into()),
    }
}

fn describe(change: &Change) {
    match change {
        Change::Added { key, new } => println!("  + {key} = {}", redact(new)),
        Change::Updated { key, old, new } => {
            println!("  ~ {key}: {} → {}", redact(old), redact(new))
        }
        Change::Removed { key, .. } => println!("  - {key}"),
    }
}

fn apply(file: &mut EnvFile, change: Change) {
    match change {
        Change::Added { key, new } | Change::Updated { key, new, .. } => file.set(key, new),
        Change::Removed { key, .. } => {
            file.remove(&key);
        }
    }
}

/// Values are secrets; show only shape, never content. Short values are
/// fully masked because a few characters can be the whole secret.
fn redact(value: &str) -> String {
    if value.len() <= 6 {
        return "*".repeat(value.len());
    }
    let shown = value.chars().take(3).collect::<String>();
    format!("{shown}{}", "*".repeat(value.len() - 3))
}
