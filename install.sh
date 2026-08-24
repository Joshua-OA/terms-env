#!/bin/sh
# terms-env installer for macOS and Linux.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/Joshua-OA/terms-env/main/install.sh | sh
#
# Options (when piping, pass them via `sh -s -- <options>`):
#   --version <tag>   install a specific release tag (default: latest release)
#   --prefix <dir>    install root; binary lands in <dir>/bin (default: ~/.local)
#   --no-verify       skip SHA-256 checksum verification (not recommended)
#   --help            show this help

set -eu

REPO="Joshua-OA/terms-env"
DOWNLOAD_URL="https://github.com/${REPO}/releases/download"
API_URL="https://api.github.com/repos/${REPO}/releases"
BINARY="tnv"

VERSION=""
PREFIX="${HOME}/.local"
VERIFY=1

log() { printf '%s\n' "$*" >&2; }
fail() { log "error: $*"; exit 1; }

usage() {
  awk 'NR >= 2 && NR <= 11 { sub(/^# ?/, ""); print } NR > 11 { exit }' "$0"
  exit 0
}

while [ $# -gt 0 ]; do
  case "$1" in
    --version)
      [ $# -ge 2 ] || fail "--version requires a tag argument"
      VERSION="$2"; shift 2 ;;
    --prefix)
      [ $# -ge 2 ] || fail "--prefix requires a directory argument"
      PREFIX="$2"; shift 2 ;;
    --no-verify) VERIFY=0; shift ;;
    -h|--help) usage ;;
    *) fail "unknown option: $1 (see --help)" ;;
  esac
done

need_cmd() { command -v "$1" >/dev/null 2>&1 || fail "$1 is required but was not found in PATH"; }

fetch() {
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL --retry 3 --retry-delay 2 -o "$2" "$1"
  elif command -v wget >/dev/null 2>&1; then
    wget -qO "$2" "$1"
  else
    fail "either curl or wget is required to download the release"
  fi
}

detect_platform() {
  os=$(uname -s)
  arch=$(uname -m)

  case "$arch" in
    x86_64|amd64) arch="x86_64" ;;
    aarch64|arm64) arch="aarch64" ;;
    *) fail "unsupported architecture: $arch" ;;
  esac

  case "${os}:${arch}" in
    Darwin:aarch64) TARGET="aarch64-apple-darwin" ;;
    Darwin:x86_64)  TARGET="x86_64-apple-darwin" ;;
    Linux:x86_64)   TARGET="x86_64-unknown-linux-gnu" ;;
    *)
      fail "no prebuilt binary for ${os} ${arch}.
Build from source instead:
  cargo install --git https://github.com/${REPO} tenv-cli"
      ;;
  esac
}

latest_tag() {
  log "resolving latest release..."
  tag=$(fetch "${API_URL}/latest" - | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -n 1)
  [ -n "$tag" ] || fail "could not resolve the latest release tag from ${API_URL}"
  printf '%s' "$tag"
}

sha256_of() {
  # Prints the lowercase SHA-256 digest of $1. Field position differs by
  # tool: sha256sum/shasum lead with the digest, openssl trails with it.
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{print $1}'
  elif command -v openssl >/dev/null 2>&1; then
    openssl dgst -sha256 "$1" | awk '{print $NF}'
  else
    return 1
  fi
}

main() {
  need_cmd uname
  detect_platform

  if [ -z "$VERSION" ]; then
    VERSION=$(latest_tag)
  fi

  asset="terms-env-${TARGET}.tar.gz"
  base="${DOWNLOAD_URL}/${VERSION}/${asset}"
  tmpdir=$(mktemp -d "${TMPDIR:-/tmp}/terms-env-install.XXXXXX")
  trap 'rm -rf "$tmpdir"' EXIT INT TERM

  log "downloading terms-env ${VERSION} for ${TARGET}..."
  fetch "${base}" "${tmpdir}/${asset}"

  if [ "$VERIFY" -eq 1 ]; then
    log "verifying SHA-256 checksum..."
    command -v sha256sum >/dev/null 2>&1 || command -v shasum >/dev/null 2>&1 || command -v openssl >/dev/null 2>&1 \
      || fail "no SHA-256 tool found (sha256sum, shasum, openssl); use --no-verify at your own risk"
    fetch "${base}.sha256" "${tmpdir}/${asset}.sha256"
    expected=$(awk '{print $1}' "${tmpdir}/${asset}.sha256")
    actual=$(sha256_of "${tmpdir}/${asset}")
    [ "$expected" = "$actual" ] || fail "checksum mismatch:
  expected: ${expected}
  actual:   ${actual}"
  else
    log "WARNING: skipping checksum verification (--no-verify)"
  fi

  tar -xzf "${tmpdir}/${asset}" -C "$tmpdir"
  [ -f "${tmpdir}/${BINARY}" ] || fail "archive did not contain the expected ${BINARY} binary"

  mkdir -p "${PREFIX}/bin"
  mv "${tmpdir}/${BINARY}" "${PREFIX}/bin/${BINARY}"
  chmod +x "${PREFIX}/bin/${BINARY}"

  case ":${PATH}:" in
    *":${PREFIX}/bin:"*) ;;
    *)
      log ""
      log "NOTE: ${PREFIX}/bin is not on your PATH. Add this to your shell profile:"
      log "  export PATH=\"${PREFIX}/bin:\$PATH\""
      ;;
  esac

  log ""
  log "installed ${BINARY} (${VERSION}, ${TARGET}) -> ${PREFIX}/bin/${BINARY}"
  log "next steps:"
  log "  ${BINARY} init          create your vault"
  log "  ${BINARY} --help        see all commands"
}

main "$@"
