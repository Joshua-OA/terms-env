# terms-env

Store and share `.env` secrets securely, terminal to terminal. No accounts,
no hosted storage of your data — an encrypted local vault plus end-to-end
encrypted handoffs via short one-time codes.

```bash
$ tnv share acme/api
    code: ember-falcon-lime-quartz

$ cd myproject && tnv receive ember-falcon-lime-quartz
```

Cross-platform (Windows / Linux / macOS), single static binary.

## Status

Early development — see [docs/PLAN.md](docs/PLAN.md) for the full architecture,
security design, and staged roadmap. Progress log lives in `docs/learnings.md`.

## Build

```bash
cargo build --release        # binary at target/release/tnv
cargo test                   # full test suite
```

## License

GPL-3.0 — see [LICENSE](LICENSE).
