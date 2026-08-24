#!/bin/sh
# terms-env uninstaller for macOS and Linux.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/Joshua-OA/terms-env/main/uninstall.sh | sh
#
# Removes the tnv binary. Your vault data is NOT touched by default —
# run `tnv uninstall` first to wipe vault + keychain key, or pass --purge
# to have this script do both.
#
# Options (when piping, pass them via `sh -s -- <options>`):
#   --prefix <dir>    install root the binary lives under (default: ~/.local)
#   --purge           also run `tnv uninstall` to wipe vault data and key
#   --help            show this help

set -eu

BINARY="tnv"
PREFIX="${HOME}/.local"
PURGE=0

log() { printf '%s\n' "$*" >&2; }
fail() { log "error: $*"; exit 1; }

usage() {
  awk 'NR >= 2 && NR <= 15 { sub(/^# ?/, ""); print } NR > 15 { exit }' "$0"
  exit 0
}

while [ $# -gt 0 ]; do
  case "$1" in
    --prefix)
      [ $# -ge 2 ] || fail "--prefix requires a directory argument"
      PREFIX="$2"; shift 2 ;;
    --purge) PURGE=1; shift ;;
    -h|--help) usage ;;
    *) fail "unknown option: $1 (see --help)" ;;
  esac
done

target="${PREFIX}/bin/${BINARY}"

if [ ! -f "$target" ]; then
  fail "tnv not found at ${target} (try --prefix if you installed elsewhere)"
fi

if [ "$PURGE" -eq 1 ]; then
  if command -v "$BINARY" >/dev/null 2>&1; then
    log "purging vault data and stored key..."
    "$BINARY" uninstall --yes || log "warning: tnv uninstall failed; data may remain"
  else
    log "warning: tnv not on PATH; skipping data purge (binary is being removed)"
  fi
else
  log "note: vault data and the keychain key are kept."
  log "run `tnv uninstall` first, or re-run this script with --purge, to wipe them."
fi

rm "$target"
rmdir "${PREFIX}/bin" 2>/dev/null || true

log "removed ${target}"
