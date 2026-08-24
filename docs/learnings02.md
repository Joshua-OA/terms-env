# learnings 02 — terms-env

Continues from `learnings.md` (Stages 0-2).

---

## Stage 3 — Vault, keychain unlock, CLI commands

### What was built
- `vault.rs`: the encrypted store. File layout per PLAN.md §5.4:
  `TNVV ‖ ver ‖ kdf_id ‖ [salt16] ‖ nonce24 ‖ ct`. Two unlock modes:
  OS keychain (production) or Argon2id master passphrase. Payload is JSON
  (projects as ordered var lists, dir→project links, device identity seed).
- **Dependency injection done properly**: vault functions take
  `&dyn KeyStore` explicitly (`OsKeyring` production / `FileKeyStore` test
  double). The library never reads env vars; only `select_keystore()` at the
  CLI boundary does (TENV_TEST_KEYSTORE). This keeps tests parallel-safe.
- `fsutil.rs`: atomic writes = temp file → fsync → rename, perms 0600 on unix.
- Fresh random nonce every save: identical data never yields identical bytes.
- CLI subcommands live: `init [--passphrase] · link · sync · add · rm · get · list`
  with `--passphrase-file` (scripts/tests) and hidden rpassword prompt on TTY,
  stdin fallback for pipes. Diff output redacts values (≤6 chars fully masked).
- Tests: 6 core vault + 7 CLI end-to-end (real binary via assert_cmd).

### What went wrong
1. First test draft mutated global env vars (TENV_HOME etc.) — races under
   Rust's parallel test harness. Caught during self-review before running.
   Redesigned to explicit injection instead. Lesson: env vars are global
   mutable state; inject dependencies through parameters.
2. links map is String-keyed but canonical() returned PathBuf — type errors
   forced the cleaner `canon_key()` helper (path → canonical string).
3. CLI test bug of my own making: both passphrase files written to the same
   `pass.txt`, second clobbered first, so the "wrong passphrase" test opened
   happily. Fixed with distinct filenames. Lesson: temp-file helpers need
   unique names or they become accidental singletons.
4. Known cost logged (not yet fixed): vault uses PRODUCTION Argon2 params
   unconditionally, so vault tests take ~70s locally. Future seam: inject
   KDF params like we do keystores if CI gets slow.

### Verified end state
46/46 tests pass · fmt clean · clippy `-D warnings` clean. Full user journey
works end-to-end in tests: init → link → add/get/list/rm → sync disk edits.

### New Rust concepts introduced
- **Trait objects (`&dyn KeyStore`)**: runtime-polymorphic dependency
  injection without generics ceremony at call sites.
- **Pattern-matching multiple error variants**:
  `Err(A | B) if supplied.is_none()` in match arms.
- **`std::io::IsTerminal`**: detect TTY without extra crates; drives
  prompt-vs-pipe behavior.
- **Exit codes**: `main() -> ExitCode` instead of unit main, so failures
  propagate proper status to shells and CI.




---

## Stage 4 — iroh transport, share/receive, blob fallback

### What was built
- `share.rs`: envelope codec per PLAN §5.1 — magic/version/mode byte layout,
  CRC32 over the frame (checked before any decryption), Argon2id
  passphrase-mode and X25519 sealed-box pubkey-mode, Ed25519 signature over a
  canonical JSON of everything except the signature itself, advisory-but-
  enforced expiry (`Expired` error on import).
- `transport/` module: 256-word list (4 words = 32-bit SPAKE2 password),
  code format `w1-w2-w3-w4-<endpoint id hex>`, wire protocol on ALPN
  `tenv/share/1`:
    receiver→sender SPAKE2 msg · sender→receiver SPAKE2 msg ·
    sender→receiver AEAD chunks + empty END marker · receiver→sender receipt
    {sha256(payload), fingerprint} · sender closes first after verifying.
  LiveShare::start returns the code immediately; wait_done awaits receipt.
  receive_live decodes+dials; receive_direct accepts a prebuilt address so
  tests run with zero DNS/relay/network.
- CLI: async main; `share [--offline|--ttl|--relay]` prints code then waits,
  auto-falls back to an offline passphrase blob if live transfer fails on a
  TTY; `receive <code>` verifies trust pinning (TOFU prompt), merges into
  linked dir + vault, writes .env atomically (auto-links fresh checkouts);
  `import <file|->`; `relay setup` scaffolds docker-compose for stock
  iroh-relay; `config relay <url|default>` persists to config.json.
- Tests: 7 envelope tests + 2 live loopback transfers (200KB payload;
  wrong-code impostor must fail closed on BOTH sides).

### What went wrong (the debugging story)
1. **Shutdown race**: receiver closed right after `send.finish()` of its
   receipt → sender's in-flight read died with "connection lost". Fix: sender
   closes FIRST (after verifying receipt); receiver waits on `conn.closed()`.
2. First fix attempt caused the mirror deadlock: both sides waited for the
   other to close because an earlier patch had left the old
   `connection.closed().await` in serve(). Lesson: shutdown ordering is ONE
   policy stated once — "the party that finishes last reads until EOF or
   closes explicitly" — and every close site must follow it.
3. Debugging blind cost several cycles; temporary eprintln tracing at each
   protocol step found it in one run ("[recv] closing" right after END marker
   exposed the missing receipt block). Removed all tracing afterwards.
4. iroh 1.0 API drift vs docs/examples online: presets via
   `Endpoint::bind(presets::N0)`, `EndpointId = PublicKey` with hex Display/
   FromStr, `RelayMap::try_from_iter`, custom relay via
   `Builder::relay_mode(RelayMode::Custom(map))`. Verified by reading vendored
   sources under ~/.cargo/registry.

### Verified end state
55/55 workspace tests · fmt/clippy clean. The full product journey now works:
`tnv share` → code → teammate `tnv receive <code>` in their project root.

### New Rust concepts introduced
- **async across crates**: sync core (vault/parser) called from async CLI fns;
  blocking Argon2 runs inline (~1s, acceptable; spawn_blocking noted as the
  upgrade path).
- **Arc<Mutex<Option<T>>> single-shot handler state** shared into a spawned
  accept task; oneshot/mpsc patterns replaced by mpsc::UnboundedSender.
- **ProtocolHandler trait impls** with associated-error constraints from iroh
  (Debug + Clone bounds shape your handler struct design).
- **Shutdown choreography** as an explicit design activity, not an
  afterthought: every `.close()` has an owner and a waiting counterpart.

---

## Stage 5 — ratatui screens with strict non-TTY degradation

### What was built
- `crates/tenv-cli/src/ui/` — three keyboard-first screens over a shared
  terminal guard (raw mode + alternate screen, Drop-restore even on panic):
  - **review**: checkbox list of Added(green)/Updated(yellow)/Removed(red)
    changes; j/k move, space toggle, a all, n none, Enter apply, q abort.
    Values masked like the plain output.
  - **trust**: first-time sender prompt — always pin / accept once / reject,
    fingerprint shown prominently.
  - **picker**: project chooser for `share` outside a linked directory.
- Wiring: `sync` and incoming-share landing both route through
  `choose_changes()` — TTY → review screen, `--yes` → everything (listed),
  pipe → default-deny listing telling you to pass --yes.
- `tnv-cli` gained a tiny `lib.rs` so integration tests can import the crate's
  UI state machines (binaries are not importable).
- 6 unit tests cover ReviewState logic: initial state, toggle isolation,
  cursor clamping, all/none, selection order, empty-input safety.

### What went wrong
1. First review.rs draft fought ListState manually (`mem::take` churn) and
   never actually rendered highlights — rewrote with stateful widget
   rendering (`render_stateful_widget`), which is the intended pattern.
2. `ListItem.style` field is private; must use `.style(...)` builder.
3. `Constraint::vertical` doesn't exist in ratatui 0.29 — use
   `Layout::default().direction(Vertical).constraints([...])`.
4. Integration test importing the bin crate failed until lib.rs existed;
   then `mod ui` in main.rs duplicated it — declaration lives ONLY in lib.rs
   now, main consumes via `tenv_cli::ui`.

### Verified end state
61/61 tests · fmt/clippy `-D warnings` clean. Non-TTY behavior unchanged:
all existing CLI e2e tests still pass untouched.

### New Rust concepts introduced
- **RAII guards**: TerminalGuard restores raw mode in Drop even when an error
  propagates via `?` — no try/finally needed.
- **lib+bin hybrid packages**: one Cargo package, two crates; lib exists for
  testability without weakening the thin-binary rule.
- **Stateful widgets**: ratatui separates widget data (List) from scroll
  state (ListState); draw borrows both each frame.

---

## Stage 6 — Hardening + release engineering

### What was built
- **Parser hardening**: `MAX_LINE_BYTES` (1 MiB) guard on logical lines —
  quote-bomb / giant-line inputs are rejected in constant time instead of
  allocating unbounded memory (import is an attack surface).
- **Fuzz-lite suite** (`tests/hardening.rs`, 5 tests): exhaustive truncation
  of a nasty fixture at every byte offset, 256 deterministic pseudo-random
  garbage inputs, over/under-limit line cases, multiline quote bomb. All
  must return clean Results, never panic.
- **Zeroize audit**: decrypted vault JSON buffer and share payload buffer
  now explicitly zeroed after parse (session keys and KDF outputs were
  already Zeroizing-wrapped from Stage 2).
- **Release pipeline** `.github/workflows/release.yml`: tag-triggered matrix
  build (macOS arm64/x64, Linux x64, Windows x64), strip, tar/zip, SHA-256
  checksums, artifacts attached to the GitHub Release via softprops v2.
  Chosen over cargo-dist to keep every line verifiable without pinning an
  external tool's schema; documented as the deviation from PLAN.md.
- **Docs**: threat-model.md, SECURITY.md policy, relay-selfhost.md, README
  rewritten; PLAN.md marked complete.

### What went wrong
1. Release build died: disk full (5.5 GiB of target/). `cargo clean`
   recovered 5+ GiB; release rebuild took ~4m41s. Lesson for CI too —
   Swatinem/rust-cache already bounds growth there.
2. A transport test flaked under full-suite parallel load (six parallel
   64 MiB Argon2 runs): my test-side 30s wall-clock starved. Isolated runs
   passed 3/3; raised the test budget to 180s with a comment. Product code
   keeps its own separate, correct timeouts.
3. Final state verified: fmt clean · clippy clean · all suites green ·
   release binary runs (`tnv --version` → 0.1.0).

### New Rust concepts introduced
- Result-typed internals made the DoS bound flow cleanly through every
  caller; explicit zeroize wipes at trust boundaries; flake triage rule:
  fix the test's wrong assumption, never weaken the product check.
