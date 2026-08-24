# learnings — terms-env

Format per stage: built / went wrong / fixed. Capped at 200 lines; overflow
continues in `learnings02.md`.

---

## Stage 0 — Foundation (workspace, toolchain, CI)

### What was built
- `docs/PLAN.md`: master reference capturing every locked decision from the
  planning session (language=Rust, transport=iroh, crypto=SPAKE2/XChaCha20/
  Argon2id/Ed25519, vault=keychain+passphrase fallback, staged roadmap 0-6).
- Cargo workspace with two crates:
  - `tenv-core` — library crate; all future logic (domain, envparser, crypto,
    vault, share, transport) as empty module stubs.
  - `tenv-cli` — binary crate producing executable `tnv`; clap-based, currently
    only `--version`.
- `.github/workflows/ci.yml` — fmt + clippy(-D warnings) + test on
  macos-14 / ubuntu-22.04 / windows-2022.
- Smoke test at `crates/tenv-core/tests/smoke.rs` (tests live outside src,
  per project convention).
- README rewritten; `.gitignore` gained `/target/`.

### What went wrong
1. Machine had no Rust toolchain (`cargo: command not found`). Installed via
   official rustup script, stable profile → cargo/rustc 1.98.0.
2. `--profile minimal` skipped `rustfmt` and `clippy` components; first
   `cargo fmt` failed with "not installed". Fixed: `rustup component add
   rustfmt clippy`. Lesson: use default profile or add components explicitly
   when scripting installs.
3. First `cargo fmt` failed twice more: forgot to create `vault.rs` and
   `transport.rs` while lib.rs already declared them. Lesson: the compiler is
   the checklist — module declarations must match files exactly.

### Verified end state
- `cargo fmt --all` clean · `cargo clippy -D warnings` clean
- `cargo test --workspace`: 1 passed
- `tnv --version` prints `tnv 0.1.0`

### New Rust concepts introduced (owner's first exposure)
- **Workspace**: one repo, several crates sharing one lockfile/target dir.
- **crate = package**: `tenv-core` (library, no main) vs `tenv-cli` (binary).
  The binary depends on the library via path dependency.
- **Module system**: `lib.rs` declares modules (`pub mod domain;`) that map to
  files; missing file = compile error, which is why fmt caught it.
- **derive macros**: `#[derive(Parser)]` generates the CLI parser from the
  struct definition — no hand-written arg parsing.
- **`env!()` macro**: compile-time env lookup; `VERSION` is baked in at build.

---

## Stage 1 — Domain models + `.env` grammar engine

### What was built
- `domain.rs`: `EnvVar {key, value}` and `EnvFile` — ordered collection with
  `get/set/remove/iter/keys`. Setting an existing key updates in place
  (position preserved); duplicates on parse collapse to last-wins.
- `envparser.rs`: full grammar per PLAN.md §"Grammar supported":
  export prefix, single/double quotes, multiline double-quoted values,
  known escapes (`\\ \" \n \t \r`), unknown escapes kept literally,
  inline comments (` #`) only for unquoted values, BOM/CRLF tolerance,
  line-numbered errors (`ParseError { line, kind }`), canonical serializer
  that quotes only when the plain form would not round-trip, plus
  `diff()` (Added/Updated/Removed) and union `merge()`.
- Design decision recorded here deliberately: **normalization over fidelity**.
  Comments/blank lines/export markers are documentation, not data — they are
  dropped so vault ↔ file diffs compare only semantic content.
- 16 tests in `crates/tenv-core/tests/envparser.rs`.

### What went wrong
1. `\"` inside double quotes kept its backslash: `unescape_double` handled
   `\n \t \r` but had no case for `"`, so it fell to the literal-backslash arm.
   Fixed by adding the explicit match arm. Lesson: escape tables need every
   pair reviewed as a table, not discovered one bug at a time.
2. Round-trip fixture used a REAL newline in an unquoted value — invalid per
   our own grammar (only double-quoted spans lines). The parser was right;
   the test fixture was wrong. Fixed the fixture. Lesson: when a test fails,
   decide which side of the contract is wrong before changing code.
3. Serializer quoted empty values (`EMPTY=""`) while dotenv convention is bare
   `EMPTY=`; both parse identically, chose convention, removed the clause.

### Verified end state
fmt clean · clippy `-D warnings` clean · 16 envparser tests + smoke pass ·
`tnv --version` still fine. Zero dependencies added to tenv-core (std only).

### New Rust concepts introduced
- **Ownership across APIs**: `diff(&base, &incoming)` borrows both files;
  returned `Change`s own cloned Strings. Borrowing = read access without
  taking ownership; clones only at the boundary where results outlive inputs.
- **Enums + exhaustive match**: `ParseErrorKind` / `Change` force every call
  site to handle all variants — add a variant later and the compiler lists
  every place that must learn about it.
- **`Result<T, E>` instead of exceptions**: parse returns `Result<EnvFile,
  ParseError>`; the `?` operator propagates errors upward concisely.
- **Iterators**: `keys()` returns `impl Iterator<Item = &str>`, lazy like
  Java streams but zero-cost; `.position()` replaces manual index loops.
- **Slices vs Vec**: parser scans `&[u8]` byte slices with an index cursor,
  converting once per logical line — cheap views, no copying while scanning.

---

## Stage 2 — Crypto core

### What was built (`crates/tenv-core/src/crypto/`)
- `kdf.rs`: Argon2id passphrase→key (64 MiB / t=3 production, 8 MiB test
  params) returning `Zeroizing<[u8;32]>`; HKDF-SHA256 for raw secrets; SHA-256.
- `aead.rs`: XChaCha20-Poly1305 one-shot seal/open plus chunk stream —
  24-byte nonce = 20-byte prefix derived via HKDF from the key (never
  transmitted) + big-endian u32 chunk counter, so chunks decrypt only in
  order.
- `spake.rs`: SPAKE2 (Ed25519 group, RFC 9382) session wrapper; shared
  identity string "terms-env" bound into the protocol.
- `sign.rs`: Ed25519 device keys, sign/verify, human fingerprint
  `XXXX-XXXX-XXXX-XXXX` from SHA-256 of the public key; seed round-trip.
- `kex.rs`: X25519 sealed boxes (ephemeral sender keypair, HKDF-derived key)
  for pubkey-mode shares and future vault-key wrapping.
- `armor.rs`: `TENV1 <mode>` header + 76-column base64 codec with strict
  validation on decode.
- 16 tests: determinism vectors, bitflip-at-start/middle/end rejection,
  truncation, wrong-key, out-of-order chunks, signature tampering, sealed-box
  wrong-recipient/tamper/short-input, SPAKE2 agreement + mismatch semantics,
  armor round-trip and malformed rejection.

### What went wrong
1. **API drift vs my memory of the crates**: spake2 0.4 uses
   `start_symmetric(&Password, &Identity)` (no `begin_symmetric`, no Result);
   chacha20poly1305's `new/encrypt/decrypt` live behind traits that must be
   imported (`aead::{KeyInit, Aead}`); x25519 public key comes from
   `PublicKey::from(&secret)`. Fixed by reading vendored crate sources in
   ~/.cargo/registry. Lesson: trust the checked-out source, not recall.
2. `Into<Payload>` ambiguity: `.as_ref().into()` didn't compile because
   several types convert to `Payload`; switched to explicit
   `Payload::from(bytes)`.
3. `-D warnings` flagged `armor()` as dead code since Stage 4 will first use
   it; correct fix was exporting it as public API, not suppressing the lint.
4. **Test-expectation bug worth remembering**: raw SPAKE2 does NOT fail on a
   wrong password — both sides derive unrelated keys and the mismatch only
   surfaces when AEAD decryption fails later. Tests now assert exactly that;
   our transport layer will treat first-decrypt-failure as handshake failure.

### Verified end state
fmt clean · clippy `-D warnings` clean · 33 tests pass (16 crypto + 16
envparser + smoke). Production Argon2 run takes ~1s locally; tests use light
params except one production-determinism check (~11s total suite).

### New Rust concepts introduced
- **Traits are imports**: capability methods like `KeyInit::new` or `Aead::
  encrypt` exist only while their trait is in scope — unlike most languages.
- **Newtypes over raw bytes**: `[u8;32]` arrays everywhere instead of loose
  Vec<u8>; fixed-size = no length bugs at API boundaries.
- **`Zeroizing<T>`**: wraps secrets so memory is wiped on drop; the type
  system carries the hygiene rule.
- **dev-dependencies**: ed25519-dalek added under `[dev-dependencies]` so
  tests can flip signature bytes without leaking it into release builds.
- **`expect()` vs `?`**: `expect` where failure is truly impossible (fixed-
  size expansion), `?` where it's a real runtime possibility.

---
