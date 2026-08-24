# terms-env — Master Build Plan

> Single source of truth. Every stage of implementation references this file.
> Status: **v0.1.0 feature-complete (Stages 0–6 delivered)** · Platform: Windows / Linux / macOS
> Deviations from original plan are recorded in docs/learnings*.md.

---

## 1. Product definition

`terms-env` is a terminal tool that stores `.env` secrets locally in an encrypted vault and shares
them between developers end-to-end encrypted using short human codes. No accounts, no hosted
storage of user data, no daemons.

```bash
$ tnv share acme/api                     # sender: prints a one-time code
    code: ember-falcon-lime-quartz

$ cd myproject && tnv receive ember-falcon-lime-quartz
    ✓ decrypted · acme/api · from ELMR-CAKE-NOVA-JOLT (pinned peer)
      + STRIPE_KEY   new
      ~ DB_URL       differs            → keep vault / take incoming?
    ✓ wrote .env (12 vars, perms 600) + saved vault copy
```

## 2. Naming

| What | Value | Verified |
|---|---|---|
| Project / repo / package | `terms-env` | chosen |
| Binary / command name | `tnv` | free on crates.io (no exact match) and npm (404) |
| Deliberately avoided | `tenv` (existing Terraform env manager), `shh`, `cryptex`, `tessera`, `sotto`, `deadbolt`, `watchword`-alternatives all taken on crates.io | checked live |

## 3. Locked decisions (with rationale)

| Decision | Choice | Why |
|---|---|---|
| Language | **Rust** | single static binary on all 3 OSes, no runtime prerequisite for receivers, smallest supply chain for a secrets tool (same reasons OpenAI moved Codex CLI TS→Rust) |
| TUI | `ratatui` + `crossterm` | native Windows Terminal/Linux/macOS, keyboard-first navigation, proven in gitui/yazi |
| CLI parsing | `clap` v4 derive | de-facto standard, type-safe subcommands |
| Transport | **iroh** library | QUIC hole-punch direct connections; falls back to blind relay servers; relays cannot read traffic (E2E by design); self-hostable `iroh-relay` binary exists |
| Default relays | n0 public community relays | live today, free, zero setup; overridable |
| Team relay | stock `iroh-relay` via Docker Compose scaffolded by `tnv relay setup` | teams run their own on VPS/on-prem; our code implements no server |
| Final fallback | offline armored blob | always works, identical crypto, zero network |
| Handshake | **SPAKE2** (RFC 9382) from the code | active MitM gets exactly one guess; no offline dictionary attacks possible |
| Payload crypto | XChaCha20-Poly1305 AEAD chunks, HKDF-SHA256 key derivation | integrity per chunk; 192-bit random nonces eliminate reuse risk |
| Sender authenticity | Ed25519 signature inside payload + fingerprint pinning (`trust`) | verifies *who* sent it, not just *that nobody tampered* |
| Passphrase mode | Argon2id KDF | memory-hard; protects weak human passphrases against offline guessing |
| Vault at rest | XChaCha20-Poly1305 file; wrapping key stored in OS keychain | macOS Keychain / Windows Credential Manager / libsecret via `keyring` crate |
| Vault fallback | Argon2id-derived key from master passphrase | for machines without usable keychains |

## 4. Architecture

```
terms-env/
├── Cargo.toml                 # workspace root (members = crates/*)
├── crates/
│   ├── tenv-cli/              # binary crate → produces executable `tnv`
│   │   ├── Cargo.toml
│   │   └── src/main.rs        # clap definitions only; delegates to tenv-core
│   └── tenv-core/             # library crate: ALL logic lives here, UI-free
│       ├── Cargo.toml
│       ├── src/lib.rs         # module declarations, public API
│       ├── src/domain.rs      # EnvFile, EnvVar, ProjectNamespace models
│       ├── src/envparser.rs   # .env grammar: quotes, export, comments, multiline
│       ├── src/crypto/        # trait CryptoEngine + SPAKE2/AEAD/KDF/signature impls
│       ├── src/vault.rs       # trait VaultStore → OsKeychain | Passphrase impls
│       ├── src/share.rs       # envelope codec, armor, CRC, expiry
│       └── src/transport.rs   # iroh wrapper: direct → relay ladder + blob export
├── crates/tenv-core/tests/    # integration/unit tests mirror modules (none inline)
├── docs/
│   ├── PLAN.md                # ← you are here
│   ├── learnings.md           # ≤200 lines per stage; overflow → learnings02.md …
│   ├── relay-selfhost.md      # team relay guide (written in Stage 4)
│   └── threat-model.md        # written in Stage 6
└── .github/workflows/ci.yml   # fmt + clippy + test on 3-OS matrix
```

Rules that keep this modular:
1. `tenv-core` never prints, never reads stdin — pure functions in, values out.
2. Every boundary is a trait (`CryptoEngine`, `VaultStore`, `Transport`) so each piece is
   swappable and mockable — Rust's answer to interfaces/DI.
3. The binary crate is thin glue: parse args → call core → render output.

## 5. Cryptographic specification

### 5.1 Share envelope (byte layout)
```
offset  size  field
0       4     magic "TENV"
4       1     version (0x01)
5       1     mode: 0x01 passphrase · 0x02 pubkey
6       …     mode material:
                  passphrase: salt[16]                      (Argon2id, 64 MiB, t=3, p=1)
                  pubkey:     ephemeral_x25519_pk[32]
…       24    xchacha20poly1305 nonce (random, fresh per envelope)
…       …     ciphertext = AEAD(payload) ‖ tag[16]
last    4     CRC32 over everything above
→ base64 armor, wrapped at 76 chars, header line "TENV1 <mode>"
```

### 5.2 Decrypted payload (authenticated plaintext)
```
project namespace (e.g. "acme/api")
created_at unix seconds · expires_at (advisory, enforced on import)
env content (ordered KEY=VALUE list)
sender Ed25519 signature over blake3(project ‖ created_at ‖ env_hash)
```

### 5.3 Handshake (live transport)
The share code encodes: protocol version ‖ channel secret (128-bit) ‖ CRC.
SPAKE2 runs over the established connection using the code as the low-entropy password;
the derived session key feeds the same XChaCha20-Poly1305 chunked stream as blob mode.
No payload byte is transmitted before handshake success. Listener accepts one session,
then tears down.

### 5.4 Vault file
```
~/.terms-env/vault.enc          XChaCha20-Poly1305 JSON payload
~/.terms-env/id.ed25519         device signing key (encrypted at rest)
key wrapping: OS keychain entry "terms-env" holds the vault key;
              fallback: Argon2id(master_passphrase)
all writes: temp file + atomic rename, perms 0600, buffers zeroized after use
```

## 6. Transport ladder (one command, graceful degradation)

```
tnv share ──► ① iroh hole-punch DIRECT QUIC        (most transfers, zero infrastructure)
              ② iroh relay fallback:
                    a. team relay if configured (TENV_RELAY / --relay / tnv config relay)
                    b. else n0 public relays (compiled-in default)
              ③ offline armored blob printed to terminal (--offline forces this)
Security invariant: crypto layer is identical on every tier; operators see ciphertext only.
```

## 7. Command surface

```
tnv init                          create vault + device keys; keychain setup
tnv link [name]                   bind current dir ↔ vault project namespace
tnv sync                          prompted diff .env ↔ vault copy (either direction)
tnv add KEY=VALUE · rm KEY · get KEY · list
tnv trust add/list/remove         pin peer fingerprints (TOFU display otherwise)
tnv pubkey                        print public key + fingerprint
tnv share [project] [--to PEER] [--offline] [--relay URL] [--ttl SECS]
tnv receive <code>
tnv import [file|-]               decrypt blob from paste/file/stdin
tnv relay setup                   scaffold docker-compose.yml (stock iroh-relay)
tnv config relay <url|default>
Global: --yes (non-interactive), --json (machine output)
```

## 8. Security invariants (checked every code review)

1. No plaintext secret ever logged, echoed, or written unencrypted.
2. Atomic writes (temp+rename), file perms 0600 on anything containing secrets.
3. All key material zeroized when out of scope (`zeroize` crate).
4. Handshake before payload, always; single-session listeners.
5. Expired blobs refused on import; unknown sender fingerprint shown for TOFU decision;
   pinned-fingerprint mismatch refuses loudly.
6. No telemetry, ever. Relay/discovery operators see ciphertext + connection metadata only.

## 9. Process conventions

- **Tests**: live exclusively in `crates/tenv-core/tests/*.rs` mirroring modules
  (`envparser.rs`, `crypto.rs`, `vault.rs`, …) plus CLI end-to-end tests spawning the real
  binary. Never inline `#[cfg(test)]` blocks — user requirement for debuggability.
- **CI gate**: `cargo fmt --check && cargo clippy -D warnings && cargo test` on
  macos-14, ubuntu-22.04, windows-2022. Branch protection: PRs must pass matrix.
- **learnings cadence**: after each stage, append `docs/learnings.md`
  (≤200 lines: what was built / what went wrong / what fixed it). Overflow → learnings02.md.
- **Teaching**: because the owner is new to Rust, every stage ends with a plain-language
  walkthrough of new concepts introduced (ownership/borrowing, traits, Result, etc.).
- **Comments in code**: minimal — names and structure carry meaning; explain *why* only where
  genuinely non-obvious. No comment noise.

## 10. Staged roadmap

| # | Deliverables | Exit criteria |
|---|---|---|
| 0 | Workspace scaffold, clap `--version`, CI matrix green, smoke test | `tnv --version` works on 3 OSes in CI |
| 1 | Domain models + full `.env` parser/diff/merge | round-trip property tests pass; edge cases covered (quotes, export, multiline, duplicates) |
| 2 | Crypto core: SPAKE2, AEAD stream, Argon2id, Ed25519, armor codec | known-answer vectors, tamper/truncation/wrong-key rejection, zeroize checks |
| 3 | Vault + keychain/fallback + CRUD + link/sync commands | restart persistence, wrong-passphrase rejection, crash-safe atomic writes |
| 4 | iroh transport ladder + share/receive + blob fallback + relay scaffold cmd | two-process e2e on all OSes; hostile-frame fail-closed; expiry refusal |
| 5 | ratatui screens: project picker, diff viewer, trust manager | non-TTY degradation keeps everything scriptable |
| 6 | Hardening + release: fuzz-lite parser, cargo-dist binaries, brew tap/scoop, README/threat-model | signed artifacts install cleanly on clean VMs |

## 11. Distribution

GitHub Releases with signed checksums (cargo-dist) → Homebrew tap, Scoop manifest,
`cargo install terms-env`. Receiving developer journey: install → `tnv receive <code>` → done.

## 12. Explicitly out of scope for v1

Accounts/orgs/RBAC/audit logs (Infisical territory), server-side sync, GUI, revocation of
already-shared blobs (mitigate: rotate the secret), post-quantum hybrid (future).

## 13. Rust concepts glossary (for first-time reading of this repo)

| Term | Plain meaning |
|---|---|
| crate | a package; workspace = repo holding several crates |
| trait | interface-like contract; `impl Trait for Type` fulfills it |
| `Result<T, E>` | recoverable error value; compiler forces handling (no exceptions) |
| `Option<T>` | explicit nullable |
| ownership/borrowing | single-owner memory model; `&x` borrows read-only, `&mut x` mutable |
| derive macros | `#[derive(Serialize)]` generates boilerplate automatically |
| cargo | build system + package manager (npm/pip equivalent) |
