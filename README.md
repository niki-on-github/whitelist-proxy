# whitelist-proxy

A small reverse proxy that exposes an upstream HTTP service to the public internet
behind an **IP whitelist**, with a web UI to manage the whitelist and inspect all
access attempts.

It is designed to sit behind a **Tailscale Funnel** configured with the
[PROXY protocol](https://tailscale.com/docs/reference/tailscale-cli/funnel#use-the-proxy-protocol)
so the real client IP is available:

```sh
tailscale funnel --proxy-protocol=2 --tls-terminated-tcp=443 tcp://127.0.0.1:8080
```

Without PROXY protocol (i.e. when reached directly), Funnel only exposes `127.0.0.1`,
which makes IP-based allow-listing useless.

## How it works

- **Proxy port** `8080` — accepts connections and **requires** a valid PROXY
  protocol header (fail-closed). Requests from an IP/CIDR on the whitelist are
  reverse-proxied to `UPSTREAM`; all others get a `403` OpenAI-compatible error.
  An empty whitelist denies everything. With `ALLOW_PATHS` set, only paths under
  the listed prefixes are proxied; everything else gets a `404`. Streaming/SSE
  responses are flushed through. `/healthz` always returns `200` and is not
  logged as an attempt.
- **Admin port** `8081` — basic-auth protected web UI + JSON API to manage the
  whitelist and to browse every access attempt (timestamp, client IP, allow/deny
  with reason, method, path, status, duration).
- State is stored in a single SQLite database (whitelist + access log).

## Configuration (environment)

| Variable | Default | Description |
|---|---|---|
| `UPSTREAM` | *(required)* | Upstream URL, e.g. `http://llama-cpp-webui.apps:8080` |
| `ADMIN_USER` | *(required)* | Basic auth user for the admin UI |
| `ADMIN_PASSWORD` | *(required)* | Basic auth password for the admin UI |
| `PROXY_LISTEN` | `0.0.0.0:8080` | Proxy listener address |
| `ADMIN_LISTEN` | `0.0.0.0:8081` | Admin listener address |
| `DB_PATH` | `data/whitelist-proxy.db` | SQLite database file |
| `LOG_RETENTION_DAYS` | `30` | Access log retention; old entries are trimmed hourly |
| `ACCEPT_PROXY` | `true` | Require a valid PROXY protocol header on the proxy port |
| `ALLOW_PATHS` | *(empty)* | Comma-separated path prefixes that may be proxied (e.g. `/v1`). Empty = all paths allowed. Other paths return `404` and are logged as denied with reason `path`. |

## Admin API

All endpoints require basic auth.

- `GET /api/whitelist` — list entries
- `POST /api/whitelist` — add entry `{"entry": "IP or CIDR", "comment": "..."}`
- `DELETE /api/whitelist/{id}` — remove entry
- `GET /api/attempts?page=&limit=&allowed=&ip=` — access log (paginated, filterable)
- `POST /api/attempts/{id}/allow` — one-click whitelist the IP of a denied attempt

## Security notes

- The proxy port rejects connections without a valid PROXY header (`ACCEPT_PROXY=true`).
  This prevents in-cluster pods from bypassing the funnel to reach the upstream.
- Client-supplied `X-Forwarded-For` / `X-Real-IP` headers are always overwritten
  with the real peer IP derived from the PROXY header / socket.
- An empty whitelist denies everything (fail-closed) — add entries via the admin UI.
- Keep the admin port out of public reach (cluster-internal only).

## Local development

```sh
go build -o whitelist-proxy .
UPSTREAM=http://127.0.0.1:11434 \
ADMIN_USER=admin ADMIN_PASSWORD=changeme \
ACCEPT_PROXY=false \
./whitelist-proxy
```

## Build

```sh
docker build -t whitelist-proxy .
```

GitHub Actions pushes images to `ghcr.io/niki-on-github/whitelist-proxy`
(`latest`, branch, `sha-*`, and `v*` tags) on push to `main` / version tags.