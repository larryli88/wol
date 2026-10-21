# wol

A tiny Wake-on-LAN web page for a home server, served through Cloudflare Tunnel and protected by Cloudflare Access.

- `app.py`: Python stdlib HTTP server plus PyJWT. It lists devices with their online status (ICMP, with a TCP probe as fallback) and sends magic packets.
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
