# Self-hosting the terms-env relay

The relay is **stock `iroh-relay`** — we ship zero server code of our own.
It is blind: it forwards encrypted packets between endpoint IDs and cannot
read any traffic. Teams that want full control of metadata (who/when/volume)
run their own; everyone else uses the free n0 community relays by default.

## 1. Scaffold

```bash
tnv relay setup          # writes ./tenv-relay/docker-compose.yml
cd tenv-relay
```

## 2. Run

```bash
docker compose up -d
```

The generated compose file binds 80/443 (iroh-relay serves plain + TLS).
Behind an existing nginx/caddy, move the ports and proxy instead — see the
upstream guide: https://github.com/n0-computer/iroh (crate `iroh-relay`).

Pin the image version to the iroh version terms-env was built against
(`IROH_RELAY_IMAGE` env var in compose; default v1.0.3).

## 3. Point clients at it

Every teammate runs once:

```bash
tnv config relay wss://relay.yourteam.example
```

Or per-invocation: `tnv share --relay wss://…` / env `TENV_RELAY`.
Reset to public defaults with `tnv config relay default`.

> Windows note: if you run without a reverse proxy, ensure the host
> certificate chain is trusted by clients (e.g. Let's Encrypt via caddy).

## 4. Verify

```bash
docker compose logs -f        # see endpoints register
tnv share                     # from a machine NOT on the relay's LAN:
                              # output shows the transfer completing
```

## What the relay can and cannot see

Cannot: payload contents (double-encrypted), project names, key values.
Can: source/destination IPs, connection times, byte volumes, endpoint IDs.

For most teams this metadata trade is fine; for sensitive orgs it is exactly
what self-hosting removes.
