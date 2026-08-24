# terms-env

Store and share `.env` secrets securely, terminal to terminal.
No accounts. No hosted storage of your data. One static binary for
Windows, Linux, and macOS.

```bash
$ tnv share acme/api
    code: ember-falcon-lime-quartz-9f86d081…

$ cd myproject
$ tnv receive ember-falcon-lime-quartz-9f86d081…
    first share from [ELMR-CAKE-NOVA-JOLT]
    Trust and pin this sender? …
    done — .env written (12 vars, perms 600) and vault updated
```

## How it works

- **Local vault** — all projects live in one encrypted file; unlocked via
  your OS keychain (Keychain / Credential Manager / libsecret) or an
  Argon2id master passphrase.
- **Sharing** — `tnv share` prints a one-time code. The receiver's `tnv`
  dials your machine directly over QUIC (iroh hole-punching); a blind relay
  is the fallback, never a middleman that can read anything. Every payload
  is end-to-end encrypted with keys derived from the code (SPAKE2), signed
  by your device key, and verified against pinned fingerprints.
- **Offline mode** — `tnv share --offline` prints a self-contained armored
  blob to carry through Slack/SSH/USB instead of a live transfer.
- **Teams** — run your own blind relay with one Docker Compose file:
  [docs/relay-selfhost.md](docs/relay-selfhost.md).

Full architecture, crypto byte-layouts, and staged roadmap:
[docs/PLAN.md](docs/PLAN.md). Security analysis: [docs/threat-model.md](docs/threat-model.md).

## Install

macOS & Linux (one-liner):

```bash
curl -fsSL https://raw.githubusercontent.com/Joshua-OA/terms-env/main/install.sh | sh
```

Windows (PowerShell):

```powershell
irm https://raw.githubusercontent.com/Joshua-OA/terms-env/main/install.ps1 | iex
```

The scripts pick the right prebuilt binary for your machine, verify it
against the SHA-256 checksum published with the release, and install:

| Platform | Binary lands in |
|---|---|
| macOS / Linux | `~/.local/bin/tnv` (PATH hint printed if needed) |
| Windows | `%LOCALAPPDATA%\Programs\terms-env\tnv.exe` (user PATH updated) |

Options: `--version vX.Y.Z` pins a release, `--prefix <dir>` changes the
install root, `--no-verify` skips checksum verification. Pass them after
`sh -s --` when piping (`... \| sh -s -- --version v0.1.0`).

From source instead (Rust 1.85+):

```bash
cargo install --path crates/tenv-cli   # or --git https://github.com/Joshua-OA/terms-env tenv-cli
tnv --version
```

Prebuilt assets per release — macOS arm64/x64, Linux x64, Windows x64,
each with a `.sha256` checksum:
https://github.com/Joshua-OA/terms-env/releases

Building from source on Linux needs `libdbus-1-dev` and `pkg-config`
(`sudo apt install libdbus-1-dev pkg-config`) for the keychain backend.
The prebuilt binaries already have this handled.

## Uninstall

Wipe vault data, relay config, and the keychain key (asks for
confirmation; `--yes` skips; `.env` files on disk are untouched):

```bash
tnv uninstall
```

Remove the binary too:

```bash
curl -fsSL https://raw.githubusercontent.com/Joshua-OA/terms-env/main/uninstall.sh | sh
```

Both in one step: `... | sh -s -- --purge`

## Daily commands

| Command | Purpose |
|---|---|
| `tnv init [--passphrase]` | create the vault |
| `tnv link [project]` | bind current directory ↔ vault namespace (`acme/api`); no name → offers the folder name |
| `tnv sync` | review `.env` edits into the vault (interactive diff screen) |
| `tnv add K=V` / `rm K` / `get K` / `list` | vault CRUD on the linked project |
| `tnv share [project]` | print a one-time code (`--offline`, `--ttl`, `--relay`) |
| `tnv receive <code>` | pull a share into the linked directory |
| `tnv import <file\|-`> | open an offline blob |
| `tnv trust` flows | pin sender fingerprints (TOFU prompt on first sight) |

Everything scriptable: `--yes` applies without prompts, non-TTY sessions
default to deny.

## Development

```bash
cargo test            # 66+ tests across 7 suites
cargo clippy --workspace --all-targets -- -D warnings
```

Progress logs live in [docs/learnings.md](docs/learnings.md) and
[docs/learnings02.md](docs/learnings02.md).

## License

GPL-3.0 — see [LICENSE](LICENSE).
