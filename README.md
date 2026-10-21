# wol

A tiny Wake-on-LAN web page for a home server, served through Cloudflare Tunnel and protected by Cloudflare Access.

- `app.py`: Python stdlib HTTP server plus PyJWT. It lists devices with their online status (ICMP, with a TCP probe as fallback) and sends magic packets.
- A background monitor polls devices every 15 s (`[monitor] interval`) and records when each one went up or down. That gives "on for 2h13m since 01:55". A change must show up in two polls in a row before it counts. The time is when the change was first seen, so it is accurate only to the poll interval, not the real boot time. `/logs` shows recent events: power on/off, wake requests (with the Access user), and service restarts.
- Optional remote shutdown (`[devices.shutdown]`). It runs `ssh user@ip "shutdown /s /t 0"` with a dedicated key from `secrets/` and the device's pinned host key. On the device, restrict the key in `authorized_keys` with `restrict,command="shutdown /s /t 0"` so it can't do anything else. The image's user uid (build arg `UID`, default 1000) must match the owner of `secrets/id_shutdown` on the host.
- State and the event log (the last 500 events) persist in the `wol-data` volume.
- Listens on `127.0.0.1:8099` only. cloudflared on the same host is the only way in.
- Every request except `/healthz` must carry a valid `Cf-Access-Jwt-Assertion`, checked against the team's certs, the application AUD and the issuer. The service refuses to start if `[access]` is not configured.
- `POST /api/wake/<id>` also requires `X-Requested-With: wol` to block CSRF.
- The container uses host networking (needed for LAN broadcast), runs as non-root, has a read-only filesystem, and drops all capabilities.

## Config

`cp config.example.toml config.toml`, then fill in `[access] team_domain` and `aud`, and add one `[[devices]]` block per machine.

## Deploy

1. Cloudflare: add your hostname (e.g. `wol.example.com`) to an Access application **first**. Then add a public hostname to the tunnel pointing to `http://localhost:8099`.
2. On the server: `git clone` this repo, create `config.toml`, then `docker compose up -d --build`.
3. To update later: `git pull && docker compose up -d --build`.

## Test

    python3 -m unittest -v test_app
