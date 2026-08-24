# learnings 03 — terms-env

Continues from `learnings02.md` (Stages 3-6).

---

## Stage 7 — Distribution: curl installers (macOS, Linux, Windows)

### What was built
- `install.sh` (repo root): POSIX `sh` installer for macOS & Linux. The
  one-liner is `curl -fsSL https://raw.githubusercontent.com/Joshua-OA/
  terms-env/main/install.sh | sh`.
  - Detects OS (`uname -s`) × arch (`uname -m`) → maps to the release
    target triple: `aarch64-apple-darwin`, `x86_64-apple-darwin`,
    `x86_64-unknown-linux-gnu`. Anything else (e.g. Linux ARM) fails with
    a pointer to `cargo install --git … tenv-cli`.
  - Resolves latest tag via the GitHub Releases API; `--version vX.Y.Z`
    pins a specific release.
  - Downloads `terms-env-<target>.tar.gz` **plus its `.sha256`** sidecar,
    verifies with whichever tool exists (`sha256sum` → `shasum -a 256` →
    `openssl dgst -sha256`). Refuses to continue on mismatch.
  - Installs to `$PREFIX/bin/tnv` (default `~/.local/bin`, no sudo),
    prints an `export PATH=…` hint when that dir isn't already on PATH.
  - Options: `--version`, `--prefix`, `--no-verify`, `--help`. All work
    through a pipe via `sh -s -- <opts>`.
- `install.ps1`: PowerShell 5.1+ installer for Windows
  (`irm …/install.ps1 | iex`). Same flow: resolves release, downloads
  `terms-env-x86_64-pc-windows-msvc.zip`, verifies via `Get-FileHash`,
  expands, copies `tnv.exe` to `%LOCALAPPDATA%\Programs\terms-env`,
  appends that dir to the **user** PATH (idempotent — checks existing
  entries first). Forces TLS 1.2 for old PS5 hosts.
- `.github/workflows/release.yml`: new `installers` job (needs `build`)
  attaches `install.sh` + `install.ps1` as assets on every tag's release,
  so users can pin the installer itself per version if they want.
- README Install section rewritten around the three paths (curl / irm /
  cargo), including the install-location table and pinning syntax.
- `Cargo.toml`: repository URL corrected from `meister/terms-env` to the
  real remote `Joshua-OA/terms-env`.

### What went wrong
1. First `--help` implementation sliced the header with
   `sed -n '2,14p'`; adding lines to the header made the range bleed into
   code, so help output ended with a stray `set -eu`. Replaced with an
   awk that stops at the first non-comment line — self-maintaining, no
   magic line numbers left behind.
2. Repo URL drift caught during setup: Cargo.toml claimed a different
   GitHub owner than the actual git remote. Any hardcoded download URL
   built from it would 404 in production. Lesson: distribution scripts
   hardcode the owner/repo string, so audit *all* metadata sources
   against `git remote -v` before shipping them.
3. **First release run hung on `macos-13` (Intel macOS) for 30+ min.**
   GitHub retired the macOS 13 runner image on Dec 4 2025 (last free
   Intel fleet); jobs on it queue forever with no error. Diagnosed by
   contrast: every other matrix job finished in 3-6 min. Fixed by
   migrating to the changelog's designated replacement label
   `macos-15-intel`. Future note: GitHub sunsets ALL Intel macOS
   runners after the macos-15 image retires (Fall 2027) — at that point
   cross-compile `x86_64-apple-darwin` on an arm64 runner instead.
4. Node 20 deprecation annotations on every job: `actions/checkout@v4`
   fixed by bumping to v5; `softprops/action-gh-release@v2` cannot be
   fixed on our side (upstream still targets Node 20; GitHub force-runs
   it on Node 24) — cosmetic only, builds unaffected.
5. **Live install test caught a real checksum-parsing bug.** The verify
   step extracted the digest with `awk '{print $NF}'` (last field) —
   correct for `openssl dgst` but wrong for `shasum`/`sha256sum`, where
   the digest is the FIRST field and the path is last. Result: every
   macOS/Linux install failed with "checksum mismatch" showing a file
   path as the "actual" value. Fixed with a per-tool `sha256_of()`
   helper. Lessons: (a) checksum tooling output formats are not
   interchangeable — parse per tool; (b) the curl|sh path is exactly
   why live smoke tests exist — this never appeared in local runs
   because macOS has `shasum`, and the bug only fired on the
   release-verify code path. Also quieted curl progress noise with
   `-sS` (errors still surface).

### Deferred (deliberate)
- **Homebrew**: skipped this stage by decision. Plan agreed on record:
  tap repo `Joshua-OA/homebrew-terms-env`, formula named `terms-env.rb`
  so users run `brew tap Joshua-OA/terms-env && brew install terms-env`;
  plain `brew install terms-env` without tapping requires getting into
  homebrew/core (~75+ stars gate), which becomes viable later. The CI
  will need a formula generator fed by the `.sha256` assets we already
  publish, plus a `TAP_TOKEN` fine-grained PAT secret scoped to the tap
  repo only.

### Verified end state
- `sh -n install.sh` clean; `--help`, unknown-flag rejection, exit codes
  exercised locally.
- Both workflow YAMLs parse cleanly.
- No remaining `meister/terms-env` references anywhere in the tree.
- Not yet verifiable locally: no release exists yet, so live end-to-end
  runs of both installers must be smoke-tested right after tagging v0.1.0
  (checklist below).

### Next-stage checklist
1. Tag `v0.1.0`, confirm all four binaries + checksums + both installers
   appear on the release.
2. Run the curl one-liner on a clean mac + Linux box; run `irm | iex` on
   a clean Windows VM; confirm PATH hint / PATH update messaging.
3. Then circle back to Homebrew per "Deferred" above.
