# Threat model

Scope: the `tnv` binary and its data at rest / in transit. Version 0.1.0.

## Assets

1. Environment secrets stored in the vault (`vault.enc`).
2. Secrets in flight during `share`/`receive`.
3. The device identity keys (Ed25519 signing, X25519 sealing) inside the vault.
4. Metadata about which projects exist and where directories are linked.

## Adversaries

| Adversary | Capability | Outcome for them |
|---|---|---|
| Network observer (ISP, coffee-shop WiFi, Slack scraper) | Sees armored blobs, share codes, QUIC packets | Ciphertext only; SPAKE2 handshake reveals nothing; codes are useless without the transfer window |
| Relay / discovery operator (n0 public relays, team relay) | Forwards all traffic, sees IPs, timing, volume | Payload is double-encrypted (our AEAD over QUIC's own encryption); metadata only |
| Active man-in-the-middle | Can tamper, replay, impersonate peers | Poly1305 rejects any modification; wrong code fails handshake before any payload moves; sender fingerprint (pinned or shown for TOFU) exposes impersonation |
| Someone who finds your laptop | Reads disk | Vault is XChaCha20-Poly1305 encrypted; key wrapped by OS keychain or Argon2id passphrase (64 MiB, t=3) |
| Malicious teammate | Receives a share legitimately | They hold what you sent them — sharing IS granting access; rotate leaked credentials instead |

## Guarantees (and their basis)

- **Confidentiality** of vault-at-rest and of every share, given key hygiene.
- **Integrity**: any flipped bit anywhere in a blob/frame is rejected
  (CRC catches transport damage early; Poly1305 catches everything else).
- **Sender authenticity** for shares: Ed25519 signature over the payload,
  verifiable against pinned fingerprints (`trust`).
- **Freshness of session keys**: every live transfer derives a new key from
  the one-time code plus fresh SPAKE2 ephemerals.

## Explicitly out of scope

- Endpoint compromise (malware, keyloggers). No local tool can defend this.
- Revocation of an already-delivered blob. Mitigation: rotate the credential.
- Coerced or shoulder-surfed passphrases; weak passphrases in passphrase mode.
- Traffic-analysis on live transfers (relay sees timing/volume).
- Side channels (memory forensics beyond best-effort `zeroize`).

## Invariants → enforcement points

| Invariant | Where |
|---|---|
| No plaintext secret logged or echoed unmasked | `redact()`/`mask()` in CLI + UI screens |
| Handshake before payload, always | `transport::serve`/`receive_over` ordering |
| Single-use listener per share | `ShareInner.payload` is `take()`n once |
| Fresh nonce per envelope/save/save-chunk | `crypto::random_nonce`, `StreamSeal` counter |
| Atomic secret writes, perms 0600 | `fsutil::atomic_write` |
| Bounded parser memory | `envparser::MAX_LINE_BYTES` |
| Expired shares refused | `share::verify_payload` |

## Reporting

See `SECURITY.md` for disclosure instructions.
